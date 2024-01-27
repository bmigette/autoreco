from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...config import DEFAULT_PROCESS_TIMEOUT, WEB_WORDLISTS_FILES_HASEXT

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
            domain = "--domain "+ self.args["domain"]
        ext = ""
        if "extensions" in self.args:
            if w in WEB_WORDLISTS_FILES_HASEXT:
                if not WEB_WORDLISTS_FILES_HASEXT[w]:
                    ext = "-x " + self.args["extensions"]
            else:
                logger.warn("file %s is not in WEB_WORDLISTS_FILES_HASEXT", w)
        output = "-o " + self.get_log_name(".log", ["extensions"])
        cmdlog = self.get_log_name(".cmd", ["extensions"])
        url = ""
        if "url" in self.args: # DNS mode does not use urls
            url = "-u " + self.args["url"]
        host = ""
        if "host" in self.args:
            host = "-H 'Host: " + self.args["host"] + "'"
        cmd = f"gobuster {mode} -w {w} {url} {host} {domain} {ext} {output}"
        logger.debug("Executing GoBuster command %s", cmd)
        ret = self.get_system_cmd_outptut(cmd, logcmdline=cmdlog, timeout=DEFAULT_PROCESS_TIMEOUT*3)

      