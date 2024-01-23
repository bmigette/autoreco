import nmap
from ..ModuleInterface import ModuleInterface
from ...logger import logger

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
        for ip, data in self.lastreturn["scan"].items():
            if "hostnames" in data and len(data["hostnames"]) > 0:
                if len(data["hostnames"]) > 1:
                    raise Exception("Many Hostnames found, not sure how would happen: "+str(data["hostnames"]))
                h = self.get_host_obj(ip)
                if data["hostnames"][0]["name"]:                    
                    h.hostname =  data["hostnames"][0]["name"]