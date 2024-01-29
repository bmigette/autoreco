from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ..common.parsers import parse_netexec_hostline
from ...TestHost import TestHost
from ...utils import is_ip

class NetExecHostScan(ModuleInterface):
    """Class to run NetExec against a single host"""

    def run(self):
        if not is_ip(self.target):
            raise ValueError("Target should be an IP: %s", self.target)
        
        protocol = "smb"
        if "protocol" in self.args:
            protocol = self.args["protocol"]
        logfile = self.get_log_name("log")
        cmdfile =  self.get_log_name("cmd")
        spider = ""
        if "spider" in self.args:
            spider = "-M spider_plus -o OUTPUT_FOLDER=" + self.get_outdir("netexec_smb_spider_plus")
        user = "anonymous"
        passw = "''"
        if "user" in self.args:
            user = "'" + self.args["user"] + "'"
        if "password" in self.args:
            passw = "'" + self.args["password"] + "'"
        action = ""
        if "action" in self.args:
            action = "--" + self.args["action"]
        self.command = f"netexec {protocol} {self.target} -u {user} -p {passw} {spider} {action} --log {logfile}"
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile)
        self.parse_output()

    def parse_output(self):
        # RPC 192.168.1.16 135 DESKTOP-78RP52H [*] Windows NT 10.0 Build 22621 (name:DESKTOP-78RP52H) (domain:DESKTOP-78RP52H)
        for line in self.output.split("\n"):
            if "(name:" not in line:
                continue
            if "[*]" in line:
                logger.debug("Processing netexec line %s", line)
                res = parse_netexec_hostline(line, True)

                logger.info("netexec processed target %s", str(self.target))
      

"""
┌──(babadmin㉿kakali) - 9:56:58 - [~/offsec/exo]
└─$ netexec smb 192.168.199.13 -u anonymous -p "" --shares -M spider_plus -o OUTPUT_FOLDER=/tmp/autoreco
SMB         192.168.199.13  445    SAMBA            [*] Windows 6.1 Build 0 (name:SAMBA) (domain:) (signing:False) (SMBv1:False)
SMB         192.168.199.13  445    SAMBA            [+] \anonymous:
SPIDER_P... 192.168.199.13  445    SAMBA            [*] Started module spidering_plus with the following options:
SPIDER_P... 192.168.199.13  445    SAMBA            [*]  DOWNLOAD_FLAG: False
SPIDER_P... 192.168.199.13  445    SAMBA            [*]     STATS_FLAG: True
SPIDER_P... 192.168.199.13  445    SAMBA            [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_P... 192.168.199.13  445    SAMBA            [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_P... 192.168.199.13  445    SAMBA            [*]  MAX_FILE_SIZE: 50 KB
SPIDER_P... 192.168.199.13  445    SAMBA            [*]  OUTPUT_FOLDER: /tmp/autoreco
SPIDER_P... 192.168.199.13  445    SAMBA            [+] Saved share-file metadata to "/tmp/autoreco/192.168.199.13.json".
SPIDER_P... 192.168.199.13  445    SAMBA            [*] SMB Shares:           3 (print$, files, IPC$)
SPIDER_P... 192.168.199.13  445    SAMBA            [*] SMB Readable Shares:  1 (files)
SPIDER_P... 192.168.199.13  445    SAMBA            [*] Total folders found:  14
SPIDER_P... 192.168.199.13  445    SAMBA            [*] Total files found:    0
"""