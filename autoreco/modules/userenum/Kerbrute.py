from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...utils import is_ip

class Kerbrute(ModuleInterface):
    """Class to run NetExec against a single host"""

    def run(self):
        if not is_ip(self.target):
            raise ValueError("Target should be an IP: %s", self.target)
        
        logfile = self.get_log_name("log")
        cmdfile =  self.get_log_name("cmd")

        domain = self.args["domain"]
        w = self.args["wordlist"]
        
        # `kerbrute userenum -d manager.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.11.236`
        self.command = f"kerbrute userenum -d {domain} {w} --dc {self.target} -o {logfile}"
        # TODO Implement Kerbrute output parsing, and make it a realtime output
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile)
