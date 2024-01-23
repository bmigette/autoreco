import nmap
from ..ModuleInterface import ModuleInterface
from ...logger import logger


class NmapSubnetPing(ModuleInterface):
    """Class to run NMAP subnet ping scan"""

    def run(self):
        nm = nmap.PortScanner()
        outname = self.get_log_name("log")
        self.lastreturn = nm.scan(self.target, None, f"-sn -T4 -oN {outname}")
        logger.debug("Finished nmap with command line %s", nm.command_line())
        xml = nm.get_nmap_last_output()
        logger.debug("XML Output: %s", xml)
        with open(self.get_log_name("xml"), "w") as f:
            f.write(str(xml))
        self.update_state()

    def update_state(self):
        for ip, data in self.lastreturn["scan"].items():
            if "hostnames" in data and len(data["hostnames"]) > 0:
                h = self.get_host_obj(ip)
                for hostname in data["hostnames"]:
                    h.add_hostname(hostname["name"])
