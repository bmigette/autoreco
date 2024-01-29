from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...config import DEFAULT_PROCESS_TIMEOUT, WEB_WORDLISTS_FILES_HASEXT
from ..common.parsers import parse_gobuster_progress
from ...TestHost import TestHost
from ...utils import is_ip_state_subnets

class GoBuster(ModuleInterface):
    """Class to run GoBuster against a single host"""

    def run(self):
        mode = "dir"
        if "mode" in self.args:
            mode = self.args["mode"]
        w = self.args["wordlist"]
        domain = ""
        if "domain" in self.args:
            domain = "--domain "+ self.args["domain"]
        ext = ""
        if "extensions" in self.args:
            if w in WEB_WORDLISTS_FILES_HASEXT:
                if not WEB_WORDLISTS_FILES_HASEXT[w]:
                    ext = "-x " + self.args["extensions"]
            else:
                logger.warn("file %s is not in WEB_WORDLISTS_FILES_HASEXT", w)
        output = "-o " + self.get_log_name(".log", ["extensions"])
        cmdlog = self.get_log_name(".cmd", ["extensions"])
        url = ""
        if "url" in self.args: # DNS mode does not use urls
            url = "-u " + self.args["url"]
        extra = ""
        if mode == "dns":
            url = f"-r {self.target}" 
            extra = "-i" # TO print IP with DNS Discovery
        host = ""
        if "host" in self.args:
            host = "-H 'Host: " + self.args["host"] + "'"
        cmd = f"gobuster {mode} -w {w} {url} {host} {domain} {ext} {extra} {output}"
        logger.debug("Executing GoBuster command %s", cmd)
        ret = self.get_system_cmd_outptut(cmd, logcmdline=cmdlog, realtime=True, progresscb=parse_gobuster_progress) 
        if mode == "dns":
            self.parse_dns_hosts(output)

    def parse_dns_hosts(self, outputfile):
        """Parses DNS Hosts and add them into state
        """
        #TODO Need Testing
        logger.debug("Parsing GoBuster DNS Result file %s", outputfile)
        with open(outputfile, "r") as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if "Found:" in line:
                line_parts = line.split(" ")
                hostname = line_parts[1]
                ips = line_parts[2].replace("[", "").replace("]", "").split(",")
                for ip in ips:
                    if is_ip_state_subnets(ip):
                        hostobject = TestHost(ip)
                        hostobject.domain = self.args["domain"]
                        hostobject.add_hostname(hostname)
    
"""
Found: mail.google.com [2a00:1450:4007:806::2005,142.250.179.69]
Found: www.google.com [2a00:1450:4007:819::2004,142.250.179.100]
Found: smtp.google.com [2a00:1450:400c:c09::1a,2a00:1450:400c:c02::1a,2a00:1450:400c:c02::1b,2a00:1450:400c:c07::1b,142.251.173.27,64.233.184.26,74.125.206.26,64.233.184.27,142.251.173.26]
Found: ns1.google.com [2001:4860:4802:32::a,216.239.32.10]
"""