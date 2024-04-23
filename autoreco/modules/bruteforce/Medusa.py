from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...config import DEFAULT_PROCESS_TIMEOUT
from ...State import State
from ..common.parsers import parse_medusa_progress

import os


class Medusa(ModuleInterface):
    """Class to run Medusa against a single host"""

    def run(self):
        self._baselogdir = os.path.join(State().TEST_WORKING_DIR, "bruteforce")
        uw = self.args["user_wordlist"]
        pw = self.args["passw_wordlist"]
        outputfile = self.get_log_name(".log")
        stdoutfile = self.get_log_name("") + ".stdout.log"

        cmdlog = self.get_log_name(".cmd")
        protocol = self.args["protocol"]
        dom = ""
        if "domain" in self.args and self.args["domain"]:
            d = self.args["domain"]
            dom = f"-m GROUP_OTHER:{d} -m GROUP:BOTH"
        cmd = f"medusa -U '{uw}' -P '{pw}' {dom} -t 4 -e ns -n {self.target_port} -O '{outputfile}' -M {protocol} -h {self.target}"
        logger.debug("Executing Medusa command %s", cmd)
        # progresscb=parse_feroxuster_progress)
        ret = self.get_system_cmd_outptut(
            cmd, logoutput=stdoutfile, logcmdline=cmdlog, realtime=True, progresscb=parse_medusa_progress)

        self.check_file_empty_and_move(outputfile)
