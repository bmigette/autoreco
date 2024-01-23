import nmap
from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...config import (
    NMAP_DEFAULT_TCP_PORT_OPTION,
    NMAP_DEFAULT_UDP_PORT_OPTION,
    NMAP_HOSTSCAN_OPTIONS,
)
from ...TestHost import TestHost


class NmapHostScan(ModuleInterface):
    """Class to run TCP/UDP scan against a single host"""

    def run(self):
        nm = nmap.PortScanner()
        outname = self.get_log_name("log")
        args = NMAP_HOSTSCAN_OPTIONS
        protocol = ""
        if "protocol" in self.args and self.args["protocol"].lower() == "udp":
            protocol = "-sU"
            if "ports" in self.args:
                ports = "-p " + ",".join(self.args["ports"])
            else:
                ports = NMAP_DEFAULT_UDP_PORT_OPTION
        else:
            if "ports" in self.args:
                ports = "-p " + ",".join(self.args["ports"])
            else:
                ports = NMAP_DEFAULT_TCP_PORT_OPTION
        nmargs = f"{args} {protocol} {ports} -oN {outname}"

        logger.debug("Starting nmap with args %s", nmargs)
        self.lastreturn = nm.scan(self.target, None, nmargs, sudo=True)
        logger.debug("Finished nmap with command line %s", nm.command_line())
        xml = nm.get_nmap_last_output()
        logger.debug("XML Output: \n %s", xml)
        with open(self.get_log_name("xml"), "w") as f:
            f.write(str(xml))
        self.update_state()

    def update_state(self):
        logger.debug("nmap scan result: \n %s", self.lastreturn)
        keys = list(self.lastreturn["scan"].keys())
        if len(keys) > 1:
            raise Exception("More than 1 IP returned ??: " + ",".join(keys))
        ip = keys[0]
        self.ip = ip
        root = self.lastreturn["scan"][keys[0]]
        hostobject = self.get_host_obj(ip)
        if "hostnames" in root and len(root["hostnames"]) > 0:
            for hostname in root["hostnames"]:
                hostobject.add_hostname(hostname)
        if "tcp" in root:
            try:
                self._update_tcp_state(root, hostobject)
            except Exception as e:
                logger.error("Error when parsing NMAP TCP Output: %s", e, exc_info=True)
        if "udp" in root:
            try:
                self._update_udp_state(root, hostobject)
            except Exception as e:
                logger.error("Error when parsing NMAP UDP Output: %s", e, exc_info=True)

        if "osmatch" in root:
            if len(root["osmatch"]) > 0:
                hostobject.os_family = root["osmatch"][0]["osclass"][0]["osfamily"]
                for match in root["osmatch"]:
                    hostobject.add_os_version(match["name"])

        hostobject.dump()

    def _update_tcp_state(self, root, hostobject: TestHost):
        for port, data in root["tcp"].items():
            if data["state"] != "open":
                continue
            hostobject.add_service(data["name"])
            hostobject.add_tcp_port(port)
            hostobject.add_tcp_service_port(data["name"], port)
            if data["product"]:
                hostobject.add_service_versions(
                    data["name"], port, data["product"], data["version"]
                )

    def _update_udp_state(self, root, hostobject: TestHost):
        for port, data in root["tcp"].items():
            if data["state"] != "open":
                continue
            hostobject.add_service(data["name"])
            hostobject.add_udp_port(port)
            hostobject.add_udp_service_port(data["name"], port)
            if data["product"]:
                hostobject.add_service_versions(
                    data["name"], port, data["product"], data["version"]
                )
