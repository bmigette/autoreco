from ..ModuleInterface import ModuleInterface
from ...logger import logger
import re
class NetExecDiscovery(ModuleInterface):
    def run(self):
        protocol = "smb"
        if "protocol" in self.args:
            protocol = self.args["protocol"]
        logfile = self.get_log_name("log")
        self.command = f"netexec {protocol} {self.target} --log {logfile}"
        self.output = self.get_system_cmd_outptut(self.command)
        self.parse_output()
            
        
    def parse_output(self):
        #RPC 192.168.1.16 135 DESKTOP-78RP52H [*] Windows NT 10.0 Build 22621 (name:DESKTOP-78RP52H) (domain:DESKTOP-78RP52H)
        for line in self.output.split("\n"):
            if "[*]" in line:
                logger.debug("Processing netexec line %s", line)
                line = re.sub('\s\s*', ' ', line)
                parts = line.split("[*]")
                protocol, hostip, port, hostname = parts[0].strip().split(" ")
                hostobj = self.get_host_obj(hostip)
                hostobj.add_service(protocol)
                hostobj.add_tcp_port(port)
                hostobj.add_tcp_service_port(protocol, port)
                if hostname.lower() != "none":
                    hostobj.hostname = hostname
                parts2 = parts[1].strip().split("(")
                os = parts2[0].strip()
                if "windows" in os.lower():
                    hostobj.os_family = "windows"
                    hostobj.os_version = os
                else:
                    hostobj.os_family = os
                name = parts2[1].split(":")[1].replace(")", "").strip()
                domain = parts2[2].split(":")[1].replace(")", "").strip()
                if domain != name:
                    hostobj.domain = domain
                logger.info("netexec processed host %s", str(hostobj))
                