from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...config import DEFAULT_PROCESS_TIMEOUT
from ..common.parsers import parse_ffuf_progress

from ...TestHost import TestHost

import json

# ffuf -H "Host: FUZZ.forestsave.lab" -ac -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://forestsave.lab 
class FFUF(ModuleInterface): 
    """Class to run FFUF against a single host"""

    def run(self):        
        domain = self.args["domain"]
        url = "-u " + self.args["url"]   
        w = self.args["wordlist"]
        mode = "vhost"
        if "mode" in self.args:
            mode = self.args["mode"]
        vhost = ""
        if mode == "vhost":
            vhost = f"-H 'Host: FUZZ.{domain}'"
        else:
            raise ValueError(f"Invalid FFUF mode: {mode}")
        
        output_log = self.get_log_name(".json")
        output_log_cmd = f"-o {output_log}" 

        cmdlog = self.get_log_name(".cmd" )
        stdout_log = self.get_log_name(".log" )
         
        
        cmd = f"ffuf -ac -w {w}:FUZZ {url} {vhost} {output_log_cmd}"
        logger.debug("Executing FFUF command %s", cmd)
        ret = self.get_system_cmd_outptut(cmd, logoutput=stdout_log, logcmdline=cmdlog, realtime=True, progresscb=parse_ffuf_progress)
        hostobj = TestHost(self.target)
        self.scan_hosts(output_log, hostobj)

        
    def scan_hosts(self, output_log, hostobj):
        try:
            with open(output_log, "r") as f:
                data = json.loads(f.read())
            for r in data["results"]:
                hostobj.add_hostname(r["host"])
        except Exception as e:
            logger.error("Error when parsing FFUF output file %s: %s", output_log, e, exc_info=True)
      