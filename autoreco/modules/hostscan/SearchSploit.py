from ..ModuleInterface import ModuleInterface
from ...logger import logger

from ...TestHost import TestHost


class SearchSploit(ModuleInterface):
    """Class to run SearchSploit against a single host"""

    def run(self):
        output = ""
        hostobject = TestHost(self.target)
        logger.info("Running searchsploit module against host %s", self.target)
        logfile = self.get_log_name("txt")
        for service_name, service_data in hostobject.service_versions.items():
            for port, data in service_data.items():
                name = data["product"]
                version = data["version"]
                # Logoutput appends by default
                output = self.get_system_cmd_outptut(f"searchsploit -t {name}", logoutput=logfile)
                logger.debug("searchsploit -t %s output: %s", name, output)
                if version:
                    output = self.get_system_cmd_outptut(f"searchsploit -t {name} {version}", logoutput=logfile)
                    logger.debug("searchsploit -t %s %s output: %s", name, version, output)
        

      