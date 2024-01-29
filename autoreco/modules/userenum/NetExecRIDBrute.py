from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ..common.parsers import parse_netexec_hostline
from ...utils import is_ip

class NetExecRIDBrute(ModuleInterface):
    """Class to run NetExec against a single host"""

    def run(self):
        if not is_ip(self.target):
            raise ValueError("Target should be an IP: %s", self.target)
        
        logfile = self.get_log_name("log")
        cmdfile =  self.get_log_name("cmd")

        user = "anonymous"
        passw = "''"
        if "user" in self.args:
            user = "'" + self.args["user"] + "'"
        if "password" in self.args:
            passw = "'" + self.args["password"] + "'"
        # TODO Test RID brute
        self.command = f"netexec smb {self.target} -u {user} -p {passw} --rid-brute 10000 --log {logfile}"
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile)

"""
┌──(babadmin㉿kakali)-[~]
└─$ crackmapexec smb 10.10.11.236 -u anonymous -p "" --rid-brute 10000
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\anonymous:
SMB         10.10.11.236    445    DC01             [+] Brute forcing RIDs
SMB         10.10.11.236    445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         10.10.11.236    445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         10.10.11.236    445    DC01             502: MANAGER\krbtgt 
"""