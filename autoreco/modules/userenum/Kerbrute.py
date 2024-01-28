from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...TestHost import TestHost

class Kerbrute(ModuleInterface):
    """Class to run NetExec against a single host"""

    def run(self):
        if not TestHost.is_ip(self.target):
            raise ValueError("Target should be an IP: %s", self.target)
        
        logfile = self.get_log_name("log")
        cmdfile =  self.get_log_name("cmd")

        user = "anonymous"
        passw = "''"
        if "user" in self.args:
            user = "'" + self.args["user"] + "'"
        if "password" in self.args:
            passw = "'" + self.args["password"] + "'"
        # TODO Implement Kerbrute
        self.command = f"netexec smb {self.target} -u {user} -p {passw} --rid-brute 10000 --log {logfile}"
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile)
