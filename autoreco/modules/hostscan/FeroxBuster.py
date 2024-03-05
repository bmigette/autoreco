from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ..common.parsers import parse_feroxuster_progress
from ...TestHost import TestHost
from ...config import DEFAULT_PROCESS_TIMEOUT, FEROXBUSTER_STATUS

import os

class FeroxBuster(ModuleInterface):
    """Class to run FeroxBuster against a single host"""

    def run(self):

        w = self.args["wordlist"]
        wext = self.args["extwordlist"]       
        outputfile = self.get_log_name(".log")
        cmdlog = self.get_log_name(".cmd")   
        url = self.args["url"]
       
        host = ""
        if "host" in self.args:
            host = "-H 'Host: " + self.args["host"] + "'"
        
        cmd = f"feroxbuster --url {url} -s {FEROXBUSTER_STATUS} -w {w} -E -x {wext} --insecure {host} -o {outputfile}"
        logger.debug("Executing FeroxBuster command %s", cmd)
        ret = self.get_system_cmd_outptut(cmd, logcmdline=cmdlog, timeout=DEFAULT_PROCESS_TIMEOUT*2) #progresscb=parse_feroxuster_progress) 
        
        self.check_file_empty_and_move(outputfile)
