from ..ModuleInterface import ModuleInterface
from ...State import State
import os

class UserEnumModuleBase(ModuleInterface):
    def __init__(self, testid, target, module_name, args={}):
        self._baselogdir = os.path.join(State().TEST_WORKING_DIR, "userenum")
        super().__init__(self, testid, target, module_name, args)