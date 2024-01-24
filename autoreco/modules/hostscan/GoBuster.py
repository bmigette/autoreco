from ..ModuleInterface import ModuleInterface
from ...logger import logger

from ...TestHost import TestHost

class GoBuster(ModuleInterface): # TODO: Support custom host via custom header
    """Class to run enum4linux against a single host"""

    def run(self):
        mode = "dir"
        if "mode" in self.args:
            mode = self.args["mode"]
        w = self.args["wordlist"]
        domain = ""
        if "domain" in self.args:
            domain = self.args["domain"]
        ext = ""
        if "extensions" in self.args:
            ext = "-x " + self.args["extensions"]
        output = "-o " + self.get_log_name(".log", ["extensions"])
        url = ""
        if "url" in self.args: #DNS mode does not use urls
            url = "-u " + self.args["url"]
        cmd = f"gobuster {mode} -w {w} {url} {domain} {ext} {output}"
        logger.debug("Executing GoBuster command %s", cmd)
        self.get_system_cmd_outptut(cmd)
      