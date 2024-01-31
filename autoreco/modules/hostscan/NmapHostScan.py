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

#TODO: Can we get the SAN from cert ? If so, parse vhosts here too

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
        if type(xml).__name__ == "bytes":
            xml = xml.decode("utf-8")
            
        logger.debug("XML Output: \n %s", xml)
        with open(self.get_log_name("xml"), "w") as f:
            f.write(str(xml))
        self.update_state()
        
    def _parse_ports(self, ports):
        """Parse Ports arguments

        Args:
            ports (any): ports, either an int list, or nmap arg format

        Returns:
            str: nmap ports args
        """
        if isinstance(ports, list):
            return "-p " + ",".join(map(str, self.args["ports"]))
        else:
            ports = str(ports)
            if "--" in ports or "-p" in ports:
                return ports
            else:
                return "-p " + ports


    def update_state(self):
        """Update state after nmap scan

        Raises:
            Exception: Parsing error
        """
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
                    )  

        hostobject.dump()
        
    def _parse_ssl_output(self, output):
        """Parses the output of ssl-cert plugin

        Args:
            output (str): ssl-cert plugin output
        """
        #'Subject: commonName=perdu.com\nSubject Alternative Name: DNS:perdu.com, DNS:*.perdu.com\nNot valid before: 2024-01-02T09:48:34\nNot valid after:  2024-04-01T09:48:33'

        logger.debug("SSL Output for host %s: %s", self.target, output)
        hostname = None
        sans = []
        for line in output.split("\n"):
            if "Subject:" in line:
                hostname = line.replace("Subject:", "").strip()
            elif "Subject Alternative Name:" in line:
                for san in line.replace("Subject Alternative Name:", "").strip().split(","):
                    if "DNS:" in san:
                        host = san.replace("DNS:","").strip()
                        if "*" in host:
                            continue # Ignore Wildcard
                        sans.append(host)
        logger.info("Hosts from certs on target %s: %s %s", self.target, hostname, sans)
        #TODO Do a lookup and verify IPs here
    
    def _update_tcp_state(self, root, hostobject: TestHost):
        """Update State with info from TCP scan

        Args:
            root (dict): TCP scan result root
            hostobject (TestHost): object to update
        """
        for port, data in root["tcp"].items():
            if data["state"] != "open":
                continue
            if int(port) == 443 or (data["name"] == "http" and "script" in data and "ssl-cert" in data["script"]):
                data["name"] = "https"
                self._parse_ssl_output(data["script"]["ssl-cert"])
                
            hostobject.add_service(data["name"])
            hostobject.add_tcp_port(port)
            hostobject.add_tcp_service_port(data["name"], port)
            if data["product"]:
                hostobject.add_service_versions(
                    data["name"], port, data["product"], data["version"]
                )

    def _update_udp_state(self, root, hostobject: TestHost):
        """Update State with info from UDP scan

        Args:
            root (dict): UDP scan result root
            hostobject (TestHost): object to update
        """
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
