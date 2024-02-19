import nmap
from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...config import  DEFAULT_PROCESS_TIMEOUT
from ...utils import is_ntlm_hash 

class Snaffler(ModuleInterface):
    """Class to run Snaffler subnet ping scan"""
    # ┌──(babadmin㉿kakali) - 11:04:42 - [/opt/autoreco]
    # └─$ python3  /opt/snafflepy/snaffler.py -d medtech -u joe -n -p Flowers1 172.16.230.0/24
    #  pysnaffler 'smb2+ntlm-password://medtech\joe:Flowers1@172.16.230.10' 172.16.230.10 --no-progress --filelist --errors --out-file /tmp/
    def run(self):
        logger.debug("Starting pysnaffler test against %s", self.target)
        logfile = self.get_log_name("log", folder="Snaffler")
        cmdfile =  self.get_log_name("cmd", folder="Snaffler")
        outputfolder = self.get_outdir("Snaffler")

        if not self.args["user"]:
            logger.warn("Snaffler module needs creds")
            return

        user = self.args["user"]
        domain = self.args["domain"]

        if is_ntlm_hash(self.args["password"]):         
            hash = self.args["password"] 
            url = f"'smb2+ntlm-nt://{domain}\{user}:{hash}@{self.target}'"
        else:
            passw = self.args["password"] 
            url = f"'smb2+ntlm-password://{domain}\{user}:{passw}@{self.target}'"

        self.command = f"pysnaffler {url} {self.target} --no-progress --filelist --errors --out-file {outputfolder}"
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile, logoutput=logfile, timeout=DEFAULT_PROCESS_TIMEOUT*3)

