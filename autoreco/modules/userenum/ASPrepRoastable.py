from .UserEnumModuleBase import UserEnumModuleBase
from ...logger import logger
from ...utils import is_ip, is_ntlm_hash

class Kerbrute(UserEnumModuleBase):
    """Class to run NetExec against a single host"""

    def run(self):
        if not is_ip(self.target):
            raise ValueError("Target should be an IP: %s", self.target)
        


        domain = self.args["domain"]
        user = self.args["user"]
        pflag = "-p"
        self.args["pmode"] = "pw" # For the filename
        logfile = self.get_log_name("log")
        cmdfile =  self.get_log_name("cmd")
        if is_ntlm_hash(self.args["password"]):
            pflag = "-hashes " + "0"*32 + ":" + self.args["password"]
        else:
            pflag += " '" + self.args["password"] + "'"
        self.command = f"impacket-GetNPUsers -dc-ip {self.target} {domain}/{user} {pflag}"
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile, logoutput=logfile)
