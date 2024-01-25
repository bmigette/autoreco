from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ..common.parsers import parse_netexec_hostline

import re


class NetExecDiscovery(ModuleInterface):
    """Class to run netexec tool for discovery"""

    def run(self):
        protocol = "smb"
        if "protocol" in self.args:
            protocol = self.args["protocol"]
        logfile = self.get_log_name("log")
        self.command = f"netexec {protocol} {self.target} --log {logfile}"
        self.output = self.get_system_cmd_outptut(self.command)
        self.parse_output()

    def parse_output(self):
        # RPC 192.168.1.16 135 DESKTOP-78RP52H [*] Windows NT 10.0 Build 22621 (name:DESKTOP-78RP52H) (domain:DESKTOP-78RP52H)
        for line in self.output.split("\n"):
            if "[*]" in line:
                logger.debug("Processing netexec line %s", line)
                res = parse_netexec_hostline(line, True)
                logger.info("netexec processed target %s", str(self.target))
