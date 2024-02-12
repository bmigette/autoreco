from .UserEnumModuleBase import UserEnumModuleBase
from ...logger import logger
from ...utils import is_ip, is_ntlm_hash

class NetExecUserEnum(UserEnumModuleBase):
    """Class to run NetExec against a single host"""
    # TODO Export userlist
    def run(self):
        if not is_ip(self.target):
            raise ValueError("Target should be an IP: %s", self.target)
        
        protocol = "smb"
        if "protocol" in self.args:
            protocol = self.args["protocol"]


        user = "anonymous"
        passw = "''"
        if "user" in self.args:
            user = "'" + self.args["user"] + "'"
        
        pflag = "-p"
        if "password" in self.args:
            self.args["pmode"] = "pw" # For the filename∂
            passw = "'" + self.args["password"] + "'"
            if is_ntlm_hash(self.args["password"]):
                pflag = "-H"
                self.args["pmode"] = "H"
        
        logfile = self.get_log_name("log", folder="NetExecUserEnum")
        cmdfile =  self.get_log_name("cmd", folder="NetExecUserEnum")
        action = ""
        if "action" in self.args and self.args["action"]:
            action = "--" + self.args["action"]
        self.command = f"netexec {protocol} {self.target} -u {user} {pflag} {passw} {action} --log {logfile}"
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile)
        #TODO: Parse output and append result into a csv file
