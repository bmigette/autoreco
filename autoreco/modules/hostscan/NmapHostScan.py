import nmap
from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...config import (
    NMAP_DEFAULT_TCP_PORT_OPTION,
    NMAP_DEFAULT_UDP_PORT_OPTION,
    NMAP_TCP_HOSTSCAN_OPTIONS,
    NMAP_UDP_HOSTSCAN_OPTIONS,
    NMAP_MAX_HOST_TIME,
)
from ...TestHost import TestHost


class NmapHostScan(ModuleInterface):
    """Class to run TCP/UDP scan against a single host"""

    def run(self):
        nm = nmap.PortScanner()
        outname = self.get_log_name("log")

        protocol = ""
        if "protocol" in self.args and self.args["protocol"].lower() == "udp":
            args = NMAP_UDP_HOSTSCAN_OPTIONS
            protocol = "-sU"
            if "ports" in self.args:
                ports = self._parse_ports(self.args["ports"])
            else:
                ports = NMAP_DEFAULT_UDP_PORT_OPTION
        else:
            args = NMAP_TCP_HOSTSCAN_OPTIONS
            if "ports" in self.args:
                ports = self._parse_ports(self.args["ports"])
            else:
                ports = NMAP_DEFAULT_TCP_PORT_OPTION
        scripts = ""
        if "script" in self.args:
            scripts = "--script=" + self.args["script"]
        nmargs = f"{args} {protocol} {ports} {scripts} -oN {outname} --host-timeout {NMAP_MAX_HOST_TIME}"

        logger.debug("Starting nmap with args %s", nmargs)
        self.lastreturn = nm.scan(self.target, None, nmargs, sudo=True)
        logger.debug("Finished nmap with command line %s", nm.command_line())
        xml = nm.get_nmap_last_output()
        logger.debug("XML Output: \n %s", xml)
        with open(self.get_log_name("xml"), "w") as f:
            f.write(str(xml))
        self.update_state()
        
    def _parse_ports(self, ports):
        if isinstance(ports, list):
            return "-p " + ",".join(map(str, self.args["ports"]))
        else:
            ports = str(ports)
            if "--" in ports or "-p" in ports:
                return ports
            else:
                return "-p " + ports


    def update_state(self):
        logger.debug("nmap scan result: \n %s", self.lastreturn)
        keys = list(self.lastreturn["scan"].keys())
        if len(keys) > 1:
            if self.target in keys:
                ip = self.target
            else:
                raise Exception(f"More than 1 IP returned, and {self.target} not in keys: " + ",".join(keys))
        else:
            ip = keys[0]
        self.ip = ip
        root = self.lastreturn["scan"][keys[0]]
        hostobject = self.get_host_obj(ip)
        if "hostnames" in root and len(root["hostnames"]) > 0:
            for hostname in root["hostnames"]:
                hostobject.add_hostname(hostname["name"])
        if "tcp" in root:
            try:
                self._update_tcp_state(root, hostobject)
            except Exception as e:
                logger.error("Error when parsing NMAP TCP Output: %s", e, exc_info=True)
                raise
        if "udp" in root:
            try:
                self._update_udp_state(root, hostobject)
            except Exception as e:
                logger.error("Error when parsing NMAP UDP Output: %s", e, exc_info=True)
                raise

        if "osmatch" in root:
            if len(root["osmatch"]) > 0:
                hostobject.os_family = root["osmatch"][0]["osclass"][0]["osfamily"]
                for match in root["osmatch"]:
                    hostobject.add_os_version(
                        match["name"]
                    )  # TODO Add certainty here ?

        hostobject.dump()

    def _update_tcp_state(self, root, hostobject: TestHost):
        for port, data in root["tcp"].items():
            if data["state"] != "open":
                continue
            if int(port) == 443 or (data["name"] == "http" and "ssl-cert" in str(data)):
                data["name"] = "https"
            hostobject.add_service(data["name"])
            hostobject.add_tcp_port(port)
            hostobject.add_tcp_service_port(data["name"], port)
            if data["product"]:
                hostobject.add_service_versions(
                    data["name"], port, data["product"], data["version"]
                )

    def _update_udp_state(self, root, hostobject: TestHost):
        for port, data in root["udp"].items():
            if "open" not in data["state"] or not data["name"]: 
                continue
            hostobject.add_service(data["name"])
            hostobject.add_udp_port(port)
            hostobject.add_udp_service_port(data["name"], port)
            if data["product"]:
                hostobject.add_service_versions(
                    data["name"], port, data["product"], data["version"]
                )
