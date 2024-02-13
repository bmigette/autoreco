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
        self._groups = None
        self._groupsfile = os.path.join(self._baselogdir, "groups.txt")
        
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
        
    def _load_groups(self):
        self._groups = []
        with open(self._groupsfile , "r") as f:
            self._groups = f.readlines()
    
    def _write_groups(self):
        logger.info("Writing %s groups in file %s", self._groupsfile , len(self._groups))
        with open(self._groupsfile , "w") as f:
            f.writelines(self._groups)
            
    def add_groups(self, groups = []):
        if not self._groups:
            self._load_groups()
        for group in groups:
            if group not in self._groups:
                logger.debug("Adding known group %s", group)
                self._groups.append(group)
        self._write_groups()
        