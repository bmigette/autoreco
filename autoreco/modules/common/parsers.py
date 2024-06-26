import re
from ...logger import logger
from ...TestHost import TestHost
from ...utils import is_valid_host, is_ip


def parse_netexec_hostline(line, update_host=False):
    data = {
        "domain": "",
        "hostname": "",
        "protocol": "",
        "port": "",
        "os_family": "",
        "os_version": "",
        "hostip": ""
    }
    try:
        line = re.sub("\s\s*", " ", line)
        parts = line.split("[*]")
        data["protocol"], data["hostip"], data["port"], data["hostname"] = parts[0].strip(
        ).split(" ")

        if data["hostname"].lower() != "none":
            data["hostname"] = data["hostname"]
        parts2 = parts[1].strip().split("(")
        os = parts2[0].strip()
        if "windows" in os.lower():
            data["os_family"] = "windows"
            data["os_version"] = os
        else:
            data["os_family"] = os
        name = parts2[1].split(":")[1].replace(")", "").strip()
        domain = parts2[2].split(":")[1].replace(")", "").strip()
        if domain.lower() != name.lower() and domain != '\x00':
            data["domain"] = domain
        logger.debug(
            "parse_netexec_hostline \n%s\n   ---->    \n%s", line, data)
        if not is_valid_host(data["hostip"]) or not is_ip(data["hostip"]):
            logger.info("Skipping IP %s because not valid", data["hostip"])
            return
        host_to_update = TestHost(data["hostip"])
        if host_to_update:
            host_to_update.add_service(data["protocol"])
            host_to_update.add_tcp_port(data["port"])
            host_to_update.add_tcp_service_port(data["protocol"], data["port"])
            if data["domain"]:
                host_to_update.domain = data["domain"]
            if "windows" in os.lower():
                host_to_update.os_family = "windows"
                host_to_update.add_os_version(os)
            else:
                host_to_update.os_family = os
            if data["hostname"] and data["hostname"].lower() != "none":
                host_to_update.add_hostname(data["hostname"])
    except Exception as e:
        logger.warn("Could not parse netxec line %s: %s",
                    line, e, exc_info=True)

    return data


def parse_gobuster_progress(lines):
    # Progress: 2903 / 220561 (1.32%)
    for line in lines.split("\n"):
        if 'Progress:' in line:
            return line.split("Progress:")[1].split(")")[0].strip()+")"
    return None


def parse_ffuf_progress(lines):
    # :: Progress: [958/4989] :: Job [1/1] :: 328 req/sec :: Duration: [0:00:03] :: Errors: 0 :
    for line in lines.split("\n"):
        if 'Progress:' in line:
            progress = line.split("Progress:")[1].split("::")[0].strip()
            try:
                p2 = progress.strip().replace(
                    "[", "").replace("]", "").split("/")
                pp = round(int(p2[0])/int(p2[1])*100, 2)
                progress += " " + str(pp) + "%"
            except Exception as e:
                logger.debug("Error when parsing progress percent: %s/%s", progress, e)
            return progress
    return None


def parse_feroxuster_progress(lines):  # doesn't work
    # "[>-------------------] - 1s      4512/573367  3m      found:63      errors:0"
    for line in lines.split("\n"):
        if '>' in line and '#' in line:
            line = re.sub("\s\s*", " ", line.strip())
            return line.split(" ")[3].strip()
    return None


medusareg = re.compile(r"(User.* )(\(\d+ of \d+, \d+ complete\))")
def parse_medusa_progress(lines):
    # "ACCOUNT CHECK: [ftp] Host: 192.168.223.147 (1 of 1, 0 complete) User: root (1 of 17, 0 complete) Password: melissa (225 of 501 complete)"
    for line in lines.split("\n"):
        res = medusareg.search(line)
        if res:
            try:
                return res.group(2)
            except Exception as e:
                logger.warn("Could not parse medusa output %s", line)
    return None
