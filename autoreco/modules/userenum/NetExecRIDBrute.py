from .UserEnumModuleBase import UserEnumModuleBase
from ...logger import logger
from ..common.parsers import parse_netexec_hostline
from ...utils import is_ip

class NetExecRIDBrute(UserEnumModuleBase):
    """Class to run NetExec against a single host"""
    # TODO Export userlist
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
        self.parse_output(self.output)
        
    def parse_output(self, output):
        users = []
        groups = []
        for line in output.split("\n"):
            try:

                if "SidTypeGroup" in line or "SidTypeAlias" in line:
                    g = line.split(":")[1].split("(")[0].strip()
                    if "\\" in g:
                        g = g.split("\\")[1]
                    groups.append(g)
                    
                if "SidTypeUser" in line and "$" not in line:
                    u = line.split(":")[1].split("(")[0].strip()
                    if "\\" in u:
                        u = u.split("\\")[1]
                    users.append(u)
                                
            except Exception as e:
                logger.error("Error processing line %s: %s", line, e, exc_info=True)
                
        if len(users)>0: 
            try:
                logger.info("Learnt RID users: %s", users)
                self.add_users(users)
            except Exception as e:
                logger.error("Error when adding RID users: %s", e, exc_info=True)
                
        if len(groups)>0: 
            try:
                logger.info("Learnt RID Groups: %s", groups)
                self.add_groups(groups)
            except Exception as e:
                logger.error("Error when adding RID groups: %s", e, exc_info=True)
        

"""
┌──(babadmin㉿kakali) - 20:14:01 - [/opt/autoreco]
└─$ netexec smb 192.168.223.70 -u pete -p "Nexus123\!" --rid-brute 10000
SMB         192.168.223.70  445    DC1              [*] Windows 10.0 Build 20348 x64 (name:DC1) (domain:corp.com) (signing:True) (SMBv1:False)
SMB         192.168.223.70  445    DC1              [+] corp.com\pete:Nexus123!
SMB         192.168.223.70  445    DC1              498: CORP\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         192.168.223.70  445    DC1              500: CORP\Administrator (SidTypeUser)
SMB         192.168.223.70  445    DC1              501: CORP\Guest (SidTypeUser)
SMB         192.168.223.70  445    DC1              502: CORP\krbtgt (SidTypeUser)
SMB         192.168.223.70  445    DC1              512: CORP\Domain Admins (SidTypeGroup)
SMB         192.168.223.70  445    DC1              513: CORP\Domain Users (SidTypeGroup)
SMB         192.168.223.70  445    DC1              514: CORP\Domain Guests (SidTypeGroup)
SMB         192.168.223.70  445    DC1              515: CORP\Domain Computers (SidTypeGroup)
SMB         192.168.223.70  445    DC1              516: CORP\Domain Controllers (SidTypeGroup)
SMB         192.168.223.70  445    DC1              517: CORP\Cert Publishers (SidTypeAlias)
SMB         192.168.223.70  445    DC1              518: CORP\Schema Admins (SidTypeGroup)
SMB         192.168.223.70  445    DC1              1118: CORP\FILES04$ (SidTypeUser) <<-------- $ = pc
SMB         192.168.223.70  445    DC1              1121: CORP\CLIENT74$ (SidTypeUser)
SMB         192.168.223.70  445    DC1              1122: CORP\CLIENT75$ (SidTypeUser)
"""