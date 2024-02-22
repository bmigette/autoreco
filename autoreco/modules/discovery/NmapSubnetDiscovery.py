import nmap
from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...config import NMAP_MAX_HOST_TIME
from ...utils import parse_nmap_ports

class NmapSubnetDiscovery(ModuleInterface):
    """Class to run NMAP subnet ping scan"""

    def run(self):
        nm = nmap.PortScanner()
        outname = self.get_log_name("log")

        if "ports" in self.args:
            ports = parse_nmap_ports(self.args["ports"])
            self.lastreturn = nm.scan(self.target, None, f"-Pn -T4 {ports} -oN {outname} --host-timeout {NMAP_MAX_HOST_TIME}m", timeout=(NMAP_MAX_HOST_TIME+1)*60)
        else:
            self.lastreturn = nm.scan(self.target, None, f"-sn -T4 -oN {outname} --host-timeout {NMAP_MAX_HOST_TIME}m", timeout=(NMAP_MAX_HOST_TIME+1)*60)

        logger.debug("Finished nmap with command line %s", nm.command_line())
        xml = nm.get_nmap_last_output()
        xml = xml.decode()
        logger.debug("XML Output: %s", xml)
        with open(self.get_log_name("xml"), "w") as f:
            f.write(str(xml))
        self.update_state()

    def update_state(self):
        if "ports" in self.args: # Port scan will show all ips even if no port up (ie host doesn't exists)
            for ip, data in self.lastreturn["scan"].items():
                if "tcp" in data and len(data["tcp"]) > 0:
                    h = self.get_host_obj(ip)
                    for hostname in data["hostnames"]:
                        h.add_hostname(hostname["name"])
        else:
            for ip, data in self.lastreturn["scan"].items():
                if "hostnames" in data and len(data["hostnames"]) > 0:
                    h = self.get_host_obj(ip)
                    for hostname in data["hostnames"]:
                        h.add_hostname(hostname["name"])
