from .UserEnumModuleBase import UserEnumModuleBase
from ...logger import logger
from ...utils import is_ip, is_ntlm_hash, get_state_dns_servers
import re


class NetExecUserEnum(UserEnumModuleBase):
    """Class to run NetExec against a single host"""
    def run(self):

        
        protocol = "smb"
        if "protocol" in self.args:
            protocol = self.args["protocol"]
        self.protocol = protocol
        target = self.target
        if not target:
            if "target_hosts" in self.args:
                target = " ".join(self.args["target_hosts"]) 
            else:
                raise Exception("No target specified")
        user = "anonymous"
        passw = "''"
        if "user" in self.args:
            user = "'" + self.args["user"] + "'"
        
        pflag = "-p"
        if "password" in self.args:
            self.args["pmode"] = "pw" # For the filename
            passw = "'" + self.args["password"] + "'"
            if is_ntlm_hash(self.args["password"]):
                pflag = "-H"
                self.args["pmode"] = "H"
        
        continue_on_success = ""
        if "continue-on-success" in self.args and self.args["continue-on-success"]:
            continue_on_success = "--continue-on-success"
        
        logfile = self.get_log_name("log", folder="NetExecUserEnum")
        cmdfile =  self.get_log_name("cmd", folder="NetExecUserEnum")
        action = ""
        if "action" in self.args and self.args["action"]:
            action = "--" + self.args["action"]
        self.command = f"netexec {protocol} {target} -u {user} {pflag} {passw} {action} {continue_on_success} --log {logfile}"
        if protocol == "ldap": 
            # See https://github.com/Pennyw0rth/NetExec/issues/184
            # TODO REMOVE FIREJAIL when this is pushed to a release: https://github.com/Pennyw0rth/NetExec/commit/2790236622eea56fb221833894ca765dc7e7a700
            dnssrv = get_state_dns_servers()[0]
            self.command = f"firejail --dns={dnssrv} {self.command}" 
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile)
        if "action" in self.args:
            if self.args["action"] == "users":
                self.parse_users_output(self.output)
            elif self.args["action"] == "groups":
                self.parse_groups_output(self.output)
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
                line = line.strip()
                if not line:
                    continue
                parts = line.split(" ")
                user = parts[4].split("\\")[1]
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
                line = line.strip()
                if not line:
                    continue
                parts = line.split(" ")
                group = " ".join(parts[4:-2]) # ['SMB', '172.16.230.10', '445', 'DC01', 'Enterprise', 'Key', 'Admins', 'membercount:', '0']
                groups.append(group)
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