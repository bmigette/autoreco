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
        searchdone = {}
        for service_name, service_data in hostobject.service_versions.items():
            logger.debug("SearchSploit Processing %s", hostobject.service_versions.items())
            for port, data in service_data.items():
                for pdata in data:
                    name = pdata["product"].strip()
                    version = pdata["version"]
                    if name in searchdone and version in searchdone[name]:
                        continue

                    # Logoutput appends by default
                    if not name in searchdone:                        
                        searchdone[name] = [version]
                        output = self.get_system_cmd_outptut(
                            f"searchsploit -t {name} --disable-colour", logoutput=logfile, logcmdinoutput=True)
                        logger.debug("searchsploit -t %s output: %s", name, output)
                        # if " " in name:
                        #     for namepart in name.split(" "):
                        #         if not namepart in searchdone:                        
                        #             searchdone[namepart] = [version]
                        #             output = self.get_system_cmd_outptut(
                        #                 f"searchsploit -t {namepart} --disable-colour", logoutput=logfile, logcmdinoutput=True)
                        #             logger.debug("searchsploit -t %s output: %s", namepart, output)
                            
                    if version:
                        searchdone[name].append(version)
                        output = self.get_system_cmd_outptut(
                            f"searchsploit -t {name} {version} --disable-colour", logoutput=logfile, logcmdinoutput=True)
                        logger.debug(
                            "searchsploit -t %s %s output: %s", name, version, output)
