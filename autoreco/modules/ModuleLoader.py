from .testModule import testModule
from .discovery.NmapSubnetPing import NmapSubnetPing
class ModuleLoader(object):
    def get_modules():
        return {
            "testModule": testModule,
            "discovery.NmapSubnetPing": NmapSubnetPing
        }