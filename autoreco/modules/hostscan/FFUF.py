from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...config import DEFAULT_PROCESS_TIMEOUT

from ...TestHost import TestHost

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
        
        output_log = "-o " + self.get_log_name(".json")

        cmdlog = self.get_log_name(".cmd" )
        stdout_log = self.get_log_name(".log" )
         
        
        cmd = f"ffuf -ac -w {w}:FUZZ {url} {vhost} {output_log}"
        logger.debug("Executing FFUF command %s", cmd)
        ret = self.get_system_cmd_outptut(cmd, logoutput=stdout_log, logcmdline=cmdlog, timeout=DEFAULT_PROCESS_TIMEOUT*3)
        self.scan_hosts(ret)

        
    def scan_hosts(self, output):
        # TODO Check if we can get vhost from logs ?
        pass
      