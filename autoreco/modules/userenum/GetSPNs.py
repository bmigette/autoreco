from .UserEnumModuleBase import UserEnumModuleBase
from ...logger import logger
from ...utils import is_ip, is_ntlm_hash

class GetSPNs(UserEnumModuleBase):
    """Class to run NetExec against a single host"""

    def run(self):
        if not is_ip(self.target):
            raise ValueError("Target should be an IP: %s", self.target)      

        domain = self.args["domain"]
        user = self.args["user"]

        self.args["pmode"] = "pw" # For the filename
        logfile = self.get_log_name("log")
        cmdfile =  self.get_log_name("cmd")
        if is_ntlm_hash(self.args["password"]):
            hashes = "-hashes :" + self.args["password"] # Thttps://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/lateral-movement-in-active-directory/active-directory-lateral-movement-techniques/pass-the-hash
            self.command = f"impacket-GetUserSPNs -dc-ip {self.target} {domain}/{user} {hashes}"
            self.args["pmode"] = "H" 
        else:
            passw = self.args["password"]
            self.command = f"impacket-GetUserSPNs -dc-ip {self.target} {domain}/{user}:'{passw}'"

        # TODO TEST / CHeck
        
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile, logoutput=logfile)
