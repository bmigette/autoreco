import re
from ...logger import logger
from ...TestHost import TestHost

def parse_netexec_hostline(line, update_host = False):
    data = {
        "domain": "",
        "hostname": "",
        "protocol": "",
        "port": "",
        "os_family": "",
        "os_version": "",
        "hostip": ""
    }
    line = re.sub("\s\s*", " ", line)
    parts = line.split("[*]")
    data["protocol"], data["hostip"], data["port"], data["hostname"] = parts[0].strip().split(" ")
    
    if data["hostname"].lower() != "none":
        data["hostname"] = data["hostname"]
    parts2 = parts[1].strip().split("(")
    os = parts2[0].strip()
    if "windows" in os.lower():
        data["os_family"] =  "windows"
        data["os_version"] = os
    else:
        data["os_family"] = os
    name = parts2[1].split(":")[1].replace(")", "").strip()
    domain = parts2[2].split(":")[1].replace(")", "").strip()
    if domain.lower() != name.lower() and domain != '\x00':
        data["domain"] = domain
    logger.debug("parse_netexec_hostline \n%s\n   ---->    \n%s", line, data)
    host_to_update = TestHost(data["hostip"])
    if host_to_update:
        host_to_update.add_service(data["protocol"])
        host_to_update.add_tcp_port(data["port"])
        host_to_update.add_tcp_service_port(data["protocol"], data["port"])
        if data["domain"]:
            host_to_update.domain = data["domain"]
        if "windows" in os.lower():
            host_to_update.os_family = "windows"
            host_to_update.add_os_version(os)
        else:
            host_to_update.os_family = os
        if data["hostname"] and data["hostname"].lower() != "none":
            host_to_update.add_hostname(data["hostname"])
    
    return data