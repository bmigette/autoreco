from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...config import FFUF_MAX_VHOST, FFUF_MAX_SAME_WORDS
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
         
        
        cmd = f"ffuf -ac -noninteractive -w {w}:FUZZ {url} {vhost} {output_log_cmd}"
        logger.debug("Executing FFUF command %s", cmd)
        ret = self.get_system_cmd_outptut(cmd, logoutput=stdout_log, logcmdline=cmdlog, realtime=True, progresscb=parse_ffuf_progress)
        hostobj = TestHost(self.target)
        self.scan_hosts(output_log, hostobj)

        
    def scan_hosts(self, output_log, hostobj):
        try:
            domain = self.args["domain"]
            with open(output_log, "r") as f:
                data = json.loads(f.read())
            if len(data["results"]) > FFUF_MAX_VHOST:
                self.status = "error"
                logger.warn("Too many results in FFUF Vhosts (%s) scan for host %s, assuming false positive", len(data["results"]) , self.args["url"])
                return 
            words = {}
            # Auto Calibration sometime gives duplicate results because size is different. Haven't foudn a way to filter on words automatically
            for r in data["results"]:
                if r["words"] in words:
                    words[r["words"]] += 1 
                else:
                    words[r["words"]] = 1
                    
            for r in data["results"]:
                host = r["host"]
                if words[r["words"]] > FFUF_MAX_SAME_WORDS:
                    logger.warn("Ignoring vhost %s because seems false positive based on similar word result %s", host, words[r["words"]])
                    continue
                if domain not in host:
                    host = f"{host}.{domain}"
                hostobj.add_hostname(host) 
        except Exception as e:
            self.status = "error"
            logger.error("Error when parsing FFUF output file %s: %s", output_log, e, exc_info=True)
      