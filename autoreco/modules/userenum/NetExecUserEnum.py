from .UserEnumModuleBase import UserEnumModuleBase
from ...logger import logger
from ...utils import is_ip, is_ntlm_hash
import re


class NetExecUserEnum(UserEnumModuleBase):
    """Class to run NetExec against a single host"""
    # TODO Export userlist
    def run(self):
        if not is_ip(self.target):
            raise ValueError("Target should be an IP: %s", self.target)
        
        protocol = "smb"
        if "protocol" in self.args:
            protocol = self.args["protocol"]
        self.protocol = protocol

        user = "anonymous"
        passw = "''"
        if "user" in self.args:
            user = "'" + self.args["user"] + "'"
        
        pflag = "-p"
        if "password" in self.args:
            self.args["pmode"] = "pw" # For the filename∂
            passw = "'" + self.args["password"] + "'"
            if is_ntlm_hash(self.args["password"]):
                pflag = "-H"
                self.args["pmode"] = "H"
        
        logfile = self.get_log_name("log", folder="NetExecUserEnum")
        cmdfile =  self.get_log_name("cmd", folder="NetExecUserEnum")
        action = ""
        if "action" in self.args and self.args["action"]:
            action = "--" + self.args["action"]
        self.command = f"netexec {protocol} {self.target} -u {user} {pflag} {passw} {action} --log {logfile}"
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile)
        #TODO: Parse output and append result into a csv file
        if self.args["action"] == "users":
            self.parse_users_output(self.output)
        elif self.args["action"] == "groups":
            self.parse_users_output(self.output)
        #

    def parse_users_output(self, output):
        users = []
        for line in output.split("\n"):
            if "[" in line and "]" in line:
                continue
            if "\\" not in line:
                continue
            
            try:                
                line = re.sub("\s\s*", " ", line)
                parts = line.strip().split(" ")
                user = parts[4].split("\\")[0]
                users.append(user)
            except Exception as e:
                logger.error("Error processing line %s: %s", line, e, exc_info=True)
            
        if len(users)>0: 
            try:
                logger.info("Learnt Netexec (%s) users: %s", self.protocol, users)
                self.add_users(users)
            except Exception as e:
                logger.error("Error when adding users: %s", e, exc_info=True)
                
    def parse_groups_output(self, output):
        groups = []
        for line in output.split("\n"):
            if not "membercount" in line:
                continue            
            try:
                line = re.sub("\s\s*", " ", line)
                parts = line.strip().split(" ")
                groups.append(parts[4])
            except Exception as e:
                logger.error("Error processing line %s: %s", line, e, exc_info=True)
                
        if len(groups)>0: 
            try:
                logger.info("Learnt Netexec (%s) Groups: %s", self.protocol, groups)
                self.add_groups(groups)
            except Exception as e:
                logger.error("Error when adding groups: %s", e, exc_info=True)

"""
┌──(babadmin㉿kakali) - 13:47:43 - [/opt/autoreco]
└─$ netexec smb 192.168.212.70 -u pete -p "Nexus123\!" --users
SMB         192.168.212.70  445    DC1              [*] Windows 10.0 Build 20348 x64 (name:DC1) (domain:corp.com) (signing:True) (SMBv1:False)
SMB         192.168.212.70  445    DC1              [+] corp.com\pete:Nexus123!
SMB         192.168.212.70  445    DC1              [*] Trying to dump local users with SAMRPC protocol
SMB         192.168.212.70  445    DC1              [+] Enumerated domain user(s)
SMB         192.168.212.70  445    DC1              corp.com\Administrator                  Built-in account for administering the computer/domain
SMB         192.168.212.70  445    DC1              corp.com\Guest                          Built-in account for guest access to the computer/domain
SMB         192.168.212.70  445    DC1              corp.com\krbtgt                         Key Distribution Center Service Account
SMB         192.168.212.70  445    DC1              corp.com\dave
SMB         192.168.212.70  445    DC1              corp.com\stephanie

┌──(babadmin㉿kakali) - 13:48:06 - [/opt/autoreco]
└─$ netexec smb 192.168.212.70 -u pete -p "Nexus123\!" --groups
SMB         192.168.212.70  445    DC1              [*] Windows 10.0 Build 20348 x64 (name:DC1) (domain:corp.com) (signing:True) (SMBv1:False)
SMB         192.168.212.70  445    DC1              [+] corp.com\pete:Nexus123!
SMB         192.168.212.70  445    DC1              [+] Enumerated domain group(s)
SMB         192.168.212.70  445    DC1              Debug                                    membercount: 0
SMB         192.168.212.70  445    DC1              Development Department                   membercount: 3
SMB         192.168.212.70  445    DC1              Management Department                    membercount: 1
SMB         192.168.212.70  445    DC1              Sales Department                         membercount: 3
SMB         192.168.212.70  445    DC1              DnsUpdateProxy                           membercount: 0

┌──(babadmin㉿kakali) - 13:48:16 - [/opt/autoreco]
└─$ netexec smb 192.168.212.70 -u pete -p "Nexus123\!" --loggedon-users
SMB         192.168.212.70  445    DC1              [*] Windows 10.0 Build 20348 x64 (name:DC1) (domain:corp.com) (signing:True) (SMBv1:False)
SMB         192.168.212.70  445    DC1              [+] corp.com\pete:Nexus123!
SMB         192.168.212.70  445    DC1              [+] Enumerated logged_on users
"""