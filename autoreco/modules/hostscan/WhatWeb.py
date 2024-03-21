from ..ModuleInterface import ModuleInterface
from ...logger import logger


class WhatWeb(ModuleInterface):
    """Class to run whatweb against a single host"""
    def run(self):
        self.web = True
        logfile = self.get_log_name("log")
        cmdfile =  self.get_log_name("cmd")
        jsonfile =  self.get_log_name("json")
        url = self.args["url"]
        host = ""
        if "host" in self.args and self.args["host"]:
            host = "-H 'Host: " + self.args["host"] + "'"
        self.command = f"whatweb --color=never --no-errors -a 3 {host} --log-verbose={logfile} --log-json={jsonfile} -v {url}"
        logger.debug("Starting whatweb with command %s", self.command)
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile)
        self.check_file_empty_and_move(logfile)


   