from .testModule import testModule

class ModuleLoader(object):
    def get_modules():
        return {
            "testModule": testModule
        }