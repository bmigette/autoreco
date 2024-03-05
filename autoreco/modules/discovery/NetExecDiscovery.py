from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ..common.parsers import parse_netexec_hostline
from ...utils import is_ntlm_hash

import re


class NetExecDiscovery(ModuleInterface):
    """Class to run netexec tool for discovery"""

    def run(self):
        protocol = "smb"
        if "protocol" in self.args:
            protocol = self.args["protocol"]
        logfile = self.get_log_name("log")
        cmdfile =  self.get_log_name("cmd")
        
        credstr = ""
        action = ""
        if "user" in self.args:
            user = "'" + self.args["user"] + "'"        
            pflag = "-p"
            self.args["pmode"] = "pw" # For the filename
            passw = "'" + self.args["password"] + "'"
            if is_ntlm_hash(self.args["password"]):
                pflag = "-H"
                self.args["pmode"] = "H"
            credstr = f"-u {user} {pflag} {passw}"
                
        if "action" in self.args and self.args["action"]:
            action = "--" + self.args["action"]
            
        self.command = f"netexec {protocol} {self.target} {credstr} {action} --log {logfile}"
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile)
        self.parse_output()

    def parse_output(self):
        # RPC 192.168.1.16 135 DESKTOP-78RP52H [*] Windows NT 10.0 Build 22621 (name:DESKTOP-78RP52H) (domain:DESKTOP-78RP52H)
        for line in self.output.split("\n"):
            if "[*]" in line and "Enumerated" not in line:
                logger.debug("Processing netexec line %s", line)
                res = parse_netexec_hostline(line, True)
                logger.info("netexec processed target %s", str(self.target))
