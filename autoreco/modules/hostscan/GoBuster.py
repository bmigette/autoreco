from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...config import DEFAULT_PROCESS_TIMEOUT, WEB_WORDLISTS_FILES_HASEXT
from ..common.parsers import parse_gobuster_progress
from ...TestHost import TestHost

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
        #TODO Implement parse_dns_hosts
        pass