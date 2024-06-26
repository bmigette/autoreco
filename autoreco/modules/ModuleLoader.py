from .SleepModule import SleepModule
from .discovery.NmapSubnetDiscovery import NmapSubnetDiscovery
from .discovery.NetExecDiscovery import NetExecDiscovery
from .hostscan.Snaffler import Snaffler
from .hostscan.SearchSploit import SearchSploit
from .hostscan.NmapHostScan import NmapHostScan
from .hostscan.Enum4Linux import Enum4Linux
from .hostscan.GoBuster import GoBuster
from .hostscan.FeroxBuster import FeroxBuster
from .hostscan.FFUF import FFUF
from .hostscan.OneSixtyOneHostScan import OneSixtyOneHostScan
from .hostscan.NetExecHostScan import NetExecHostScan
from .hostscan.RPCDump import RPCDump
from .hostscan.WhatWeb import WhatWeb
from .hostscan.WKHtmlToImage import WKHtmlToImage
from .hostscan.Certipy import Certipy
from .userenum.Kerbrute import Kerbrute
from .userenum.NetExecRIDBrute import NetExecRIDBrute
from .userenum.NetExecUserEnum import NetExecUserEnum
from .userenum.ASPrepRoastable import ASPrepRoastable
from .userenum.GetSPNs import GetSPNs
from .bruteforce.Medusa import Medusa

class ModuleLoader(object):
    """Load all known modules and maps it to a string"""

    def get_modules():
        return {
            "SleepModule": SleepModule,
            "discovery.NmapSubnetDiscovery": NmapSubnetDiscovery,
            "discovery.NetExecDiscovery": NetExecDiscovery,
            "hostscan.Snaffler": Snaffler,
            "hostscan.SearchSploit": SearchSploit,
            "hostscan.NmapHostScan": NmapHostScan,
            "hostscan.Enum4Linux": Enum4Linux,
            "hostscan.GoBuster": GoBuster,
            "hostscan.FeroxBuster": FeroxBuster,            
            "hostscan.NetExecHostScan": NetExecHostScan,
            "hostscan.FFUF": FFUF,
            "hostscan.OneSixtyOneHostScan": OneSixtyOneHostScan,
            "hostscan.RPCDump": RPCDump,     
            "hostscan.WKHtmlToImage": WKHtmlToImage,  
            "hostscan.WhatWeb": WhatWeb,         
            "hostscan.Certipy": Certipy,
            "userenum.Kerbrute": Kerbrute,
            "userenum.NetExecRIDBrute": NetExecRIDBrute,
            "userenum.NetExecUserEnum": NetExecUserEnum,
            "userenum.ASPrepRoastable": ASPrepRoastable,
            "userenum.GetSPNs": GetSPNs,
            "bruteforce.Medusa": Medusa            
        }
