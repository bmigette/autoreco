from ..ModuleInterface import ModuleInterface
from ...logger import logger


class OneSixtyOneHostScan(ModuleInterface):
    """Class to run OneSixtyOne against a single host"""

    def run(self):
        port = self.args["port"]
        wordlist = self.args["wordlist"]
        logfile = self.get_log_name("log")
        cmdfile =  self.get_log_name("cmd")
        self.command = f"onesixtyone {self.target} -c {wordlist} -p {port} -o {logfile}"
        logger.debug("Starting SNMP Scan with command %s", self.command)
        #TODO: use realtime scan ? wordlist is small though
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile)
        self.check_file_empty_and_move(logfile)

   