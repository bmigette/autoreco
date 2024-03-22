from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ..common.parsers import parse_feroxuster_progress
from ...TestHost import TestHost
from ...config import DEFAULT_PROCESS_TIMEOUT, HTTP_REQ_TIMEOUT_SEC, FEROXBUSTER_EXTLIST
from ...config import FEROXBUSTER_STATUS_EXCLUDE, FEROXBUSTER_THREADS

import os


class FeroxBuster(ModuleInterface):
    """Class to run FeroxBuster against a single host"""

    def run(self):
        self.web = True
        w = self.args["wordlist"]
        outputfile = self.get_log_name(".log")
        stdout = self.get_log_name("")  + "stdout.log"
        cmdlog = self.get_log_name(".cmd")
        url = self.args["url"]

        host = ""
        if "host" in self.args:
            host = "-H 'Host: " + self.args["host"] + "'"
        cmd = f"feroxbuster -t {FEROXBUSTER_THREADS} --timeout {HTTP_REQ_TIMEOUT_SEC} --url {url} -C {FEROXBUSTER_STATUS_EXCLUDE} -w {w} -E -x '{FEROXBUSTER_EXTLIST}' --insecure {host} -o {outputfile} --auto-tune"
        logger.debug("Executing FeroxBuster command %s", cmd)
        # progresscb=parse_feroxuster_progress)
        ret = self.get_system_cmd_outptut(
            cmd, logcmdline=cmdlog, logoutput=stdout, timeout=DEFAULT_PROCESS_TIMEOUT*2)

        self.check_file_empty_and_move(outputfile)
