from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...utils import is_ntlm_hash
from ...TestHost import TestHost


class Enum4Linux(ModuleInterface):
    """Class to run enum4linux against a single host"""

    def run(self):
        logfile = self.get_log_name("", folder="enum4linux")
        if "user" in self.args and "password" in self.args:
            
            user, passw = self.args["user"], self.args["password"]
            if is_ntlm_hash(passw):
                logger.debug("Skipping enum4linux test because of NTLM hash not supported for user %s", user)
                return
            self.get_system_cmd_outptut(f"enum4linux-ng -A {self.target} -u {user} -p {passw} -oA {logfile}", logoutput=logfile+".log",  logcmdline=logfile+".cmd")
        else:
            self.get_system_cmd_outptut(f"enum4linux-ng -A {self.target} -oA {logfile}", logoutput=logfile+".log", logcmdline=logfile+".cmd")
