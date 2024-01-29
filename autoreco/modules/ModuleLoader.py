from .testModule import testModule
from .discovery.NmapSubnetPing import NmapSubnetPing
from .discovery.NetExecDiscovery import NetExecDiscovery
from .hostscan.NmapHostScan import NmapHostScan
from .hostscan.Enum4Linux import Enum4Linux
from .hostscan.GoBuster import GoBuster
from .hostscan.FFUF import FFUF
from .hostscan.NetExecHostScan import NetExecHostScan
from .userenum.Kerbrute import Kerbrute
from .userenum.NetExecRIDBrute import NetExecRIDBrute
from .userenum.NetExecUserEnum import NetExecUserEnum

class ModuleLoader(object):
    """Load all known modules and maps it to a string"""

    def get_modules():
        return {
            "testModule": testModule,
            "discovery.NmapSubnetPing": NmapSubnetPing,
            "discovery.NetExecDiscovery": NetExecDiscovery,
            "hostscan.NmapHostScan": NmapHostScan,
            "hostscan.Enum4Linux": Enum4Linux,
            "hostscan.GoBuster": GoBuster,
            "hostscan.NetExecHostScan": NetExecHostScan,
            "hostscan.FFUF": FFUF,
            "userenum.Kerbrute": Kerbrute,
            "userenum.NetExecRIDBrute": NetExecRIDBrute,
            "userenum.NetExecUserEnum": NetExecUserEnum,
            
        }
