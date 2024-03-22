from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ..common.parsers import parse_feroxuster_progress
from ...TestHost import TestHost
from ...config import DEFAULT_PROCESS_TIMEOUT, HTTP_REQ_TIMEOUT_SEC, FEROXBUSTER_EXTLIST
from ...config import FEROXBUSTER_STATUS_EXCLUDE, FEROXBUSTER_THREADS

import os


class Medusa(ModuleInterface):
    """Class to run Medusa against a single host"""

    def run(self):
        uw = self.args["user_wordlist"]
        pw = self.args["passw_wordlist"]
        outputfile = self.get_log_name(".log")
        cmdlog = self.get_log_name(".cmd")
        protocol = self.args["protocol"]

        cmd = f"medusa -U '{uw}' -P '{pw}' -e ns -n {self.target_port} -O '{outputfile}' -M {protocol} -h {self.target}"
        logger.debug("Executing Medusa command %s", cmd)
        # progresscb=parse_feroxuster_progress)
        ret = self.get_system_cmd_outptut(
            cmd, logcmdline=cmdlog, timeout=DEFAULT_PROCESS_TIMEOUT*2)

        self.check_file_empty_and_move(outputfile)
