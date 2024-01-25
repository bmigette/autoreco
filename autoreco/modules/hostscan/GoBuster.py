from ..ModuleInterface import ModuleInterface
from ...logger import logger

from ...TestHost import TestHost

class GoBuster(ModuleInterface):
    """Class to run GoBuster against a single host"""

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
        if "url" in self.args: # DNS mode does not use urls
            url = "-u " + self.args["url"]
        host = ""
        if "host" in self.args:
            host = "-H 'Host: " + self.args["host"] + "'"
        cmd = f"gobuster {mode} -w {w} {url} {domain} {ext} {output}"
        logger.debug("Executing GoBuster command %s", cmd)
        ret = self.get_system_cmd_outptut(cmd)
        self.scan_hosts(ret)

    def scan_hosts(self, output):
        # TODO
        pass
      