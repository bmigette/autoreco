import os
from .logger import logger
from .State import State
from .config import DEFAULT_MAX_OUTPUT, EXCLUDE_HOSTS
import re
import dns.resolver
from pathlib import Path

def max_output(thestr:str , max = DEFAULT_MAX_OUTPUT):
    if not isinstance(thestr, str):
        return thestr
    if len(thestr) > max:
        return thestr[:max] +"\ ---- output omitted ----"
    else:
        return thestr



def parse_nmap_ports( ports):
    """Parse Ports arguments

    Args:
        ports (any): ports, either an int list, or nmap arg format

    Returns:
        str: nmap ports args
    """
    if isinstance(ports, list):
        return "-p " + ",".join(map(str, ports))
    else:
        ports = str(ports)
        if "--" in ports or "-p" in ports:
            return ports
        else:
            return "-p " + ports
        
            
def print_summary():
    total_tests = 0
    total_hosts = 0
    success_tests = 0
    failed_tests = 0
    started_tests = 0
    ignored = 0
    from .WorkThreader import WorkThreader

    state = State().TEST_STATE.copy()
    for host, data in state.items():
        total_hosts += 1
        if "tests_state" in data:
            for testid, testdata in data["tests_state"].items():
                total_tests += 1
                if testdata["state"] == "done":
                    success_tests += 1
                elif testdata["state"] == "error":
                    failed_tests += 1
                elif testdata["state"] == "started":
                    started_tests += 1
                elif testdata["state"] == "ignored":
                    ignored += 1
                    
                else:
                    pass
                    # logger.warn("Test %s state: %s", testid, testdata["state"])

    logger.info("=" * 50)
    logger.info(
        "# Running / Ran %s Tests against %s hosts", total_tests, total_hosts
    )
    logger.info(
        "# Success: %s, Failed: %s, Running: %s, Queued: %s, Ignored: %s",
        success_tests,
        failed_tests,
        started_tests,
        WorkThreader.queue.qsize(),
        ignored
    )
    logger.info("=" * 50)


def is_ip(ip: str):
    """Check if a string is an IP

    Args:
        ip (str): IP Address

    Returns:
        bool: yes or no
    """
    if not ip:
        return False
    match = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", ip)
    return bool(match)

def is_ntlm_hash(passw: str):
    """Check if a given string is a NTLM Hash

    Args:
        passw (str): Password / Hash

    Returns:
        bool: True if matches NTLM Hash Format
    """
    match = re.match(r"[a-fA-F0-9]{32}", passw)
    return bool(match)

#https://www.dnspython.org/examples.html

def resolve_domain(domain: str, dnserver: str = None):
    try:
        if dnserver:
            answer = dns.resolver.resolve_at(dnserver, domain, "A")
        else:
            answer = dns.resolver.resolve(domain, "A")
    except Exception as e:
        logger.error("Error in DNS Resolution for domain %s: %s", domain, e)
        return []
    
    return [x.to_text() for x in answer]
        
def get_state_subnets():
    subnets = []
    state = State().TEST_STATE.copy()
    for k, v in state.items():
        if k == "discovery" and "tests_state" in v:
            for testname, testdata in v["tests_state"].items():
                if "target" not in testdata:
                    logger.error("No target in %s / %s", testname, testdata)
                else:
                    subnets.append(testdata["target"].split("/")[0])
        ip_parts = k.split(".")
        ip_parts[-1] = "0"
        subnet = ".".join(ip_parts)
        if subnet not in subnets:
            subnets.append(subnet)
    return subnets

def get_state_dns_servers():
    from .TestHost import TestHost
    dns = []
    state = State().TEST_STATE.copy()
    for k, v in state.items():
        if k == "discovery":
            continue
        hostobj = TestHost(k)
        if "domain" in hostobj.services:  
            dns.append(k)
    logger.debug("Known DNS servers: %s", dns)
    return dns

def is_ip_state_subnets(ip: str, subnets = None): 
    """Checks if an IP is in same subnets that hosts in state to avoid scanning the internet :D

    Args:
        ip (str): The IP ADdress
    """
    # Yes, this could be improved
    if not subnets:
        subnets = get_state_subnets()
    ip_parts = ip.split(".")
    ip_parts[-1] = "0"
    subnet = ".".join(ip_parts)
    return subnet in subnets

def remove_ansi_escape_chars(input): 
    #https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
    # 7-bit and 8-bit C1 ANSI sequences
    ansi_escape_8bit = re.compile(r'''
        (?: # either 7-bit C1, two bytes, ESC Fe (omitting CSI)
            \x1B
            [@-Z\\-_]
        |   # or a single 8-bit byte Fe (omitting CSI)
            [\x80-\x9A\x9C-\x9F]
        |   # or CSI + control codes
            (?: # 7-bit CSI, ESC [ 
                \x1B\[
            |   # 8-bit CSI, 9B
                \x9B
            )
            [0-?]*  # Parameter bytes
            [ -/]*  # Intermediate bytes
            [@-~]   # Final byte
        )
    ''', re.VERBOSE)
    result = ansi_escape_8bit.sub('', input)
    return result


def flatten_args(argsin, argusekey=[], ignorekeys=["password", "pass"]):
    """strip bad chars and flatten args to make unique log file names

    Args:
        argusekey (list, optional): Will use the arg key instead of values for all keys in this list. Defaults to [].
        ignorekeys (list, optional): Ignore all keys in this list. Defaults to [].

    Returns:
        str: flattened args
    """
    args = []
    for k, v in argsin.items():
        if k.lower() in [x.lower() for x in ignorekeys]:
            continue
        if k in argusekey:
            v = k+str(len(v))
        else:
            if isinstance(v, list):
                v = "+".join(map(str, v))
            v = str(v)
            if os.path.isfile(v):
                v = Path(v).stem
            v.replace(",", "+")
        args.append(re.sub(r"[^a-zA-Z0-9\.\+\-_]+", "_", v))
    return "-".join(args)


def is_valid_host(ip):
    if not is_ip(ip):
        return False
    parts = ip.split(".")
    if parts[-1] in EXCLUDE_HOSTS:
        return False
    
    return True


def is_file_empty(file):
    if not os.path.exists(file):
        return True
    
    #with open (file , "r") as f:
    import codecs
    with codecs.open(file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    if len(content.strip()) < 1:
        return True
    return False