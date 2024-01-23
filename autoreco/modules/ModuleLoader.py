from .testModule import testModule
from .discovery.NmapSubnetPing import NmapSubnetPing
from .discovery.NetExecDiscovery import NetExecDiscovery
from .hostscan.NmapHostScan import NmapHostScan


class ModuleLoader(object):
    """Load all known modules and maps it to a string"""

    def get_modules():
        return {
            "testModule": testModule,
            "discovery.NmapSubnetPing": NmapSubnetPing,
            "discovery.NetExecDiscovery": NetExecDiscovery,
            "hostscan.NmapHostScan": NmapHostScan,
        }
