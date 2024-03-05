from ..ModuleInterface import ModuleInterface
from ...logger import logger

from ...utils import is_ntlm_hash


class RPCDump(ModuleInterface):
    """Class to run enum4linux against a single host"""

    def run(self):
        logfile = self.get_log_name("")
        user, passw = self.args["user"], self.args["password"]
        if is_ntlm_hash(passw):
            self.get_system_cmd_outptut(f"rpcdump.py {user}:'{passw}'@{self.target}", logoutput=logfile+".log",  logcmdline=logfile+".cmd")
        else:
            self.get_system_cmd_outptut(f"rpcdump.py -hashes 00000000000000000000000000000000:{passw} {user}@{self.target}", logoutput=logfile+".log",  logcmdline=logfile+".cmd")
