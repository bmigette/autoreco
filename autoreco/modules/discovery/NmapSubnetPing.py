import nmap
from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...state import statelock, TEST_STATE

class NmapSubnetPing(ModuleInterface):
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
        with statelock:
            for ip, data in self.lastreturn["scan"].items():
                if ip not in TEST_STATE:
                    TEST_STATE[ip] = {"ip": ip}
                hostnamesdata = data["hostnames"] if "hostnames" in data else []
                TEST_STATE[ip]["hostnames"] = [x["name"] for x in hostnamesdata]