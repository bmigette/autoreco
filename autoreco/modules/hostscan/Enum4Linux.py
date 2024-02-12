from ..ModuleInterface import ModuleInterface
from ...logger import logger

from ...TestHost import TestHost


class Enum4Linux(ModuleInterface):
    """Class to run enum4linux against a single host"""

    def run(self):
        logfile = self.get_log_name("")
        if "user" in self.args and "password" in self.args:
            user, passw = self.args["user"], self.args["password"]
            self.get_system_cmd_outptut(f"enum4linux-ng -A {self.target} -u {user} -p {passw} -oA {logfile}", logoutput=logfile+".log",  logcmdline=logfile+".cmd")
        else:
            self.get_system_cmd_outptut(f"enum4linux-ng -A {self.target} -oA {logfile}", logoutput=logfile+".log", logcmdline=logfile+".cmd")
