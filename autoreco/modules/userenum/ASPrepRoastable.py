from .UserEnumModuleBase import UserEnumModuleBase
from ...logger import logger
from ...utils import is_ip, is_ntlm_hash

class ASPrepRoastable(UserEnumModuleBase):
    """Class to run NetExec against a single host"""

    def run(self):
        if not is_ip(self.target):
            raise ValueError("Target should be an IP: %s", self.target)      

        domain = self.args["domain"]
        user = self.args["user"]
        pflag = "-p"
        self.args["pmode"] = "pw" # For the filename
        logfile = self.get_log_name("log")
        cmdfile =  self.get_log_name("cmd")
        if is_ntlm_hash(self.args["password"]):
            hashes = "-hashes :" + self.args["password"] # Thttps://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/lateral-movement-in-active-directory/active-directory-lateral-movement-techniques/pass-the-hash
            self.command = f"impacket-GetNPUsers -dc-ip {self.target} {domain}/{user} {hashes}"
            self.args["pmode"] = "H" 
        else:
            passw = self.args["password"]
            self.command = f"impacket-GetNPUsers -dc-ip {self.target} {domain}/{user}:'{passw}'"

        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile, logoutput=logfile)
        self.parse_output(self.output)
        
    def parse_output(self, output):
        start = False
        users = []
        groups = []
        for line in output.split("\n"):
            try:
                if not start:
                    if "---" in line:
                        start = True
                    continue
                parts = line.strip().split(" ")
                users.append(parts[0])
                groups.append(parts[0])
                
            except Exception as e:
                logger.error("Error processing line %s: %s", line, e, exc_info=True)
                
        if len(users)>0: 
            try:
                logger.info("Learnt Roastable users: %s", users)
                self.add_users(users)
            except Exception as e:
                logger.error("Error when adding users: %s", e, exc_info=True)
                
        if len(groups)>0: 
            try:
                logger.info("Learnt Roastable Users's Groups: %s", groups)
                self.add_groups(groups)
            except Exception as e:
                logger.error("Error when adding groups: %s", e, exc_info=True)
        
            
        
"""
Impacket v0.11.0 - Copyright 2023 Fortra

Name  MemberOf                                  PasswordLastSet             LastLogon                   UAC
----  ----------------------------------------  --------------------------  --------------------------  --------
dave  CN=Development Department,DC=corp,DC=com  2022-09-07 18:54:57.521205  2024-02-13 13:30:28.204303  0x410200
"""