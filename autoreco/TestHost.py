from .State import State
from .logger import logger
from .utils import is_ip
import re
import json

"""
Format is {
    "1.2.3.4": {
        "ip": "1.2.3.4",
        "hostnames": ["host.xxx.com"],
        "domain": "xxx.com"
        "os_family": "windows",
        "os_version": ["windows 10 xxx"],
        "services": ["http", "dns"],
        "tcp_ports": [80, 8080, 443],
        "udp_ports": [80, 8080, 443],
        "tcp_service_ports": {
            "http": [80, 8080]
        },
        "udp_service_ports": {
            "dns": [53]
        },
        service_versions : {
            "http" : {
                80: [{
                    "product": "Microsoft HTTPAPI httpd",
                    "version": "2.0"
                }]
            }
        }
        tests_state : {
            "xxxx" : {
                "module_name": "moduleName",
                "args": "",
                "state": "done"
            }
        }
    }
}
"""


class TestHost:
    """This class represent a test host object (can also be a generic 'discovery' host)
    It is responsible of accessing and updating the global state for that host with test result etc...
    """

    def __init__(self, ip: str):
        self.ip = ip
        self.check_host(ip)



    def check_host(self, hostip: str):
        """Check if a host is already in state

        Args:
            hostip (str): the host ip

        Raises:
            ValueError: invalid ip
        """
        if not "discovery" in hostip and not is_ip(hostip):
            raise ValueError(f"{hostip} is not an IP or discovery")
        if hostip not in State().TEST_STATE:
            State().TEST_STATE[hostip] = {}

    def _state_field_get(self, fieldname, default_value = None):
        if self.ip not in State().TEST_STATE or fieldname not in State().TEST_STATE[self.ip]:
            return default_value
        return State().TEST_STATE[self.ip][fieldname]

    def _state_field_set(self, fieldname, value):
        State().TEST_STATE[self.ip][fieldname] = value

    def _state_field_exists(self, fieldname):
        return fieldname in State().TEST_STATE[self.ip]

    @property
    def hostnames(self):
        return self._state_field_get("hostnames", [])

    @hostnames.setter
    def hostnames(self, value):
        return self._state_field_set("hostnames", value)

    @property
    def domain(self):
        return self._state_field_get("domain")

    @domain.setter
    def domain(self, value):
        return self._state_field_set("domain", value)

    @property
    def os_family(self):
        return self._state_field_get("os_family")

    @os_family.setter
    def os_family(self, value):
        return self._state_field_set("os_family", value)

    @property
    def os_version(self):
        return self._state_field_get("os_version")

    @os_version.setter
    def os_version(self, value):
        if not self._state_field_exists("os_version") or len(
            self._state_field_get("os_version")
        ) < len(value):
            return self._state_field_set("os_version", value)

    @property
    def services(self):
        return self._state_field_get("services", [])

    @services.setter
    def services(self, value):
        return self._state_field_set("services", set(value))

    @property
    def service_versions(self):
        return self._state_field_get("service_versions", {})

    @service_versions.setter
    def service_versions(self, value):
        return self._state_field_set("service_versions", set(value))
    
    @property
    def tcp_ports(self):
        return self._state_field_get("tcp_ports", [])

    @tcp_ports.setter
    def tcp_ports(self, value):
        return self._state_field_set("tcp_ports", set(value))

    @property
    def udp_ports(self):
        return self._state_field_get("udp_ports", [])

    @udp_ports.setter
    def udp_ports(self, value):
        return self._state_field_set("udp_ports", set(value))

    @property
    def tcp_service_ports(self):
        return self._state_field_get("tcp_service_ports", {})

    @tcp_service_ports.setter
    def tcp_service_ports(self, value):
        return self._state_field_set("tcp_service_ports", value)

    @property
    def udp_service_ports(self):
        return self._state_field_get("udp_service_ports", {})

    @udp_service_ports.setter
    def udp_service_ports(self, value):
        return self._state_field_set("udp_service_ports", value)

    @property
    def tests_state(self):
        return self._state_field_get("tests_state", {})

    @tests_state.setter
    def tests_state(self, value):
        return self._state_field_set("tests_state", value)

    def has_test(self, testid):
        if not self._state_field_exists("tests_state"):
            return False
        return testid in self.tests_state

    def add_tcp_service_port(self, service: str, port: int):
        """Add a TCP Service port entry

        Args:
            service (str): service name, example http
            port (int): port number
        """
        if not service:
            logger.warn("Skipping empty tcp service with port %s", port)
            return
        service = service.lower()
        
        with State().statelock:
            if "tcp_service_ports" not in State().TEST_STATE[self.ip]:
                State().TEST_STATE[self.ip]["tcp_service_ports"] = {service: [int(port)]}
            else:
                if service not in State().TEST_STATE[self.ip]["tcp_service_ports"]:
                    State().TEST_STATE[self.ip]["tcp_service_ports"][service] = []
                if int(port) not in State().TEST_STATE[self.ip]["tcp_service_ports"][service]:
                    State().TEST_STATE[self.ip]["tcp_service_ports"][service].append(int(port))

    def _has_product_version(self, slist, product, version):
        """Checks if a product / version already exists in state

        Args:
            slist (list): state list to look into
            product (str): product
            version (str): version
        """
        for item in slist:
            if item["product"] == product and item["version"] == version:
                return True
        return False

    def add_service_versions(self, service: str, port: int, product: str, version: str):
        """Add a TCP Service port entry

        Args:
            service (str): service name, example http
            port (int): port number
            product (str): product
            version (str): version
        """
        if not service or not product:
            logger.warn("Skipping empty service version with port %s", port)
            return
        service = service.lower()
        
        with State().statelock:
            if "service_versions" not in State().TEST_STATE[self.ip]:
                State().TEST_STATE[self.ip]["service_versions"] = {
                    service: {int(port): [{"product": product, "version": version}]}
                }
            else:
                if service not in State().TEST_STATE[self.ip]["service_versions"]:
                    State().TEST_STATE[self.ip]["service_versions"][service] = {}
                if int(port) not in State().TEST_STATE[self.ip]["service_versions"][service]:
                    State().TEST_STATE[self.ip]["service_versions"][service][int(port)] = []
                if not self._has_product_version(
                    State().TEST_STATE[self.ip]["service_versions"][service][int(port)],
                    product,
                    version,
                ):
                    State().TEST_STATE[self.ip]["service_versions"][service][int(port)].append(
                        {"product": product, "version": version}
                    )

    def add_udp_service_port(self, service: str, port: int):
        """Add a UDP Service port entry

        Args:
            service (str): service name, example http
            port (int): port number
        """
        if not service:
            logger.warn("Skipping empty udp service with port %s", port)
            return
        service = service.lower()
        
        with State().statelock:
            if "udp_service_ports" not in State().TEST_STATE[self.ip]:
                State().TEST_STATE[self.ip]["udp_service_ports"] = {service: [int(port)]}
            else:
                if service not in State().TEST_STATE[self.ip]["udp_service_ports"]:
                    State().TEST_STATE[self.ip]["udp_service_ports"][service] = []
                if int(port) not in State().TEST_STATE[self.ip]["udp_service_ports"][service]:
                    State().TEST_STATE[self.ip]["udp_service_ports"][service].append(int(port))

    def add_os_version(self, os_version: str):
        """Add a os_version

        Args:
            os_version (str): os_version name, example Windows 10 x64
        """
        
        with State().statelock:
            if "os_version" not in State().TEST_STATE[self.ip]:
                State().TEST_STATE[self.ip]["os_version"] = [os_version]
            else:
                if os_version not in State().TEST_STATE[self.ip]["os_version"]:
                    State().TEST_STATE[self.ip]["os_version"].append(os_version)

    def add_hostname(self, hostname: str):
        # Also what is this stupid none
        # 2024-01-24 22:55:55,370 - Thread-8 (thread_consumer) - TestHost - DEBUG - Skipping Invalid hostname...
        # NoneType: None
        """Add a hostname. We use a list, because not all modules / tools gives the same hostname

        Args:
            hostname (str): hostname  example win2k12
        """
        if not hostname or len(hostname) < 1:
            return
        
        with State().statelock:
            if "hostnames" not in State().TEST_STATE[self.ip]:
                State().TEST_STATE[self.ip]["hostnames"] = [hostname]
            else:
                if hostname not in State().TEST_STATE[self.ip]["hostnames"]:
                    State().TEST_STATE[self.ip]["hostnames"].append(hostname)

    def add_service(self, service: str):
        """Add a Service

        Args:
            service (str): service name, example http
        """
        if not service:
            return
        
        service = service.lower()
        with State().statelock:
            if "services" not in State().TEST_STATE[self.ip]:
                State().TEST_STATE[self.ip]["services"] = [service]
            else:
                if service not in State().TEST_STATE[self.ip]["services"]:
                    State().TEST_STATE[self.ip]["services"].append(service)

    def add_tcp_port(self, port):
        """Add a TCP port

        Args:
            port (int): service port, example 80
        """
        
        with State().statelock:
            if "tcp_ports" not in State().TEST_STATE[self.ip]:
                State().TEST_STATE[self.ip]["tcp_ports"] = [int(port)]
            else:
                if int(port) not in State().TEST_STATE[self.ip]["tcp_ports"]:
                    State().TEST_STATE[self.ip]["tcp_ports"].append(int(port))

    def add_udp_port(self, port):
        """Add a UDP Port

        Args:
            port (int): service port, example 53
        """
        
        with State().statelock:
            if "udp_ports" not in State().TEST_STATE[self.ip]:
                State().TEST_STATE[self.ip]["udp_ports"] = [int(port)]
            else:
                if int(port) not in State().TEST_STATE[self.ip]["udp_ports"]:
                    State().TEST_STATE[self.ip]["udp_ports"].append(int(port))

    def set_test_state(
        self,
        testid: str,
        state: str,
        module_name: str = None,
        target: str = None,        
        args: list = None,
    ):
        """Set test state. Omitted values won't override what's in state

        Args:
            testid (str): test id
            state (str): test state
            module_name (str, optional): Module Name. Defaults to None.
            target (str, optional): target . Defaults to None.
            args (list, optional): args. Defaults to None.
        """
        if "tests_state" not in State().TEST_STATE[self.ip]:
            State().TEST_STATE[self.ip]["tests_state"] = {}
        if testid not in State().TEST_STATE[self.ip]["tests_state"]:
            State().TEST_STATE[self.ip]["tests_state"][testid] = {"state": state}
        else:
            State().TEST_STATE[self.ip]["tests_state"][testid]["state"] = state
        if module_name is not None:
            State().TEST_STATE[self.ip]["tests_state"][testid]["module_name"] = module_name
        if target is not None:
            State().TEST_STATE[self.ip]["tests_state"][testid]["target"] = target
        if args is not None:
            State().TEST_STATE[self.ip]["tests_state"][testid]["args"] = args

    def __repr__(self):
        return f"{self.ip} - {self.hostnames} - {self.os_family}"

    def dump(self):
        logger.debug(
            "Dump of %s: \n %s", self.ip, json.dumps(State().TEST_STATE[self.ip], indent=4)
        )
