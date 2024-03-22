from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...utils import is_ntlm_hash

class Certipy(ModuleInterface):
    """Class to run Certipy against a single host"""

    def run(self):
        self.web = True
        logfile = self.get_log_name("log")
        cmdfile = self.get_log_name("cmd")
        
        user = self.args["user"]
        domain = self.args["domain"]

        if is_ntlm_hash(self.args["password"]):
            password = "-hashes " + self.args["password"]
        else:
            password = "-p '" + self.args["password"] + "'"

        self.command = f"certipy find -u {user}@{domain} {password} -target-ip {self.target} -dc-ip {self.target} -ns {self.target} -text -stdout"
        logger.debug("Starting certipy with command %s", self.command)
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile, logoutput=logfile)


   