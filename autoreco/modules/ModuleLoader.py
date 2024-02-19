from .testModule import testModule
from .discovery.NmapSubnetPing import NmapSubnetPing
from .discovery.NetExecDiscovery import NetExecDiscovery
from .hostscan.Snaffler import Snaffler
from .hostscan.SearchSploit import SearchSploit
from .hostscan.NmapHostScan import NmapHostScan
from .hostscan.Enum4Linux import Enum4Linux
from .hostscan.GoBuster import GoBuster
from .hostscan.FFUF import FFUF
from .hostscan.OneSixtyOneHostScan import OneSixtyOneHostScan
from .hostscan.NetExecHostScan import NetExecHostScan
from .userenum.Kerbrute import Kerbrute
from .userenum.NetExecRIDBrute import NetExecRIDBrute
from .userenum.NetExecUserEnum import NetExecUserEnum
from .userenum.ASPrepRoastable import ASPrepRoastable
from .userenum.GetSPNs import GetSPNs

class ModuleLoader(object):
    """Load all known modules and maps it to a string"""

    def get_modules():
        return {
            "testModule": testModule,
            "discovery.NmapSubnetPing": NmapSubnetPing,
            "discovery.NetExecDiscovery": NetExecDiscovery,
            "hostscan.Snaffler": Snaffler,
            "hostscan.SearchSploit": SearchSploit,
            "hostscan.NmapHostScan": NmapHostScan,
            "hostscan.Enum4Linux": Enum4Linux,
            "hostscan.GoBuster": GoBuster,
            "hostscan.NetExecHostScan": NetExecHostScan,
            "hostscan.FFUF": FFUF,
            "hostscan.OneSixtyOneHostScan": OneSixtyOneHostScan,
            "userenum.Kerbrute": Kerbrute,
            "userenum.NetExecRIDBrute": NetExecRIDBrute,
            "userenum.NetExecUserEnum": NetExecUserEnum,
            "userenum.ASPrepRoastable": ASPrepRoastable,
            "userenum.GetSPNs": GetSPNs,
            
        }
