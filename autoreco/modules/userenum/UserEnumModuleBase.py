from ..ModuleInterface import ModuleInterface
from ...State import State
from ...logger import logger
import os

class UserEnumModuleBase(ModuleInterface):
    def __init__(self, testid, target, module_name, args={}):        
        super().__init__(self, testid, target, module_name, args)
        self._baselogdir = os.path.join(State().TEST_WORKING_DIR, "userenum")
        self._usehostinlogdir = False
        self._users = None
        self._userfile = os.path.join(self._baselogdir, "users.txt")
        
    def _load_users(self):
        self._users = []
        with open(self._userfile , "r") as f:
            self._users = f.readlines()
    
    def _write_users(self):
        logger.info("Writing %s users in file %s", self._userfile , len(self._users))
        with open(self._userfile , "w") as f:
            f.writelines(self._users)
            
    def add_users(self, users = []):
        if not self._users:
            self._load_users()
        for user in users:
            if user not in self._users:
                logger.debug("Adding known user %s", user)
                self._users.append(user)
        self._write_users()
        