from .testModule import testModule
from .discovery.NmapSubnetPing import NmapSubnetPing
from .discovery.NetExecDiscovery import NetExecDiscovery

class ModuleLoader(object):
    def get_modules():
        return {
            "testModule": testModule,
            "discovery.NmapSubnetPing": NmapSubnetPing,
            "discovery.NetExecDiscovery": NetExecDiscovery
        }