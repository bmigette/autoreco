from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ..common.parsers import parse_netexec_hostline
from ...utils import is_ip

class NetExecUserEnum(ModuleInterface):
    """Class to run NetExec against a single host"""
    
     #TODO Support NTLM Pass The Hash
    def run(self):
        if not is_ip(self.target):
            raise ValueError("Target should be an IP: %s", self.target)
        
        protocol = "smb"
        if "protocol" in self.args:
            protocol = self.args["protocol"]
        logfile = self.get_log_name("log")
        cmdfile =  self.get_log_name("cmd")

        user = "anonymous"
        passw = "''"
        if "user" in self.args:
            user = "'" + self.args["user"] + "'"
        if "password" in self.args:
            passw = "'" + self.args["password"] + "'"
        action = ""
        if "action" in self.args:
            action = "--" + self.args["action"]
        self.command = f"netexec {protocol} {self.target} -u {user} -p {passw} {action} --log {logfile}"
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile)
