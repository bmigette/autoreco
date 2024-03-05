from ..ModuleInterface import ModuleInterface
from ...State import State
from ...logger import logger
import os

class UserEnumModuleBase(ModuleInterface):
    def __init__(self, testid, target, module_name, args={}):        
        super().__init__(testid, target, module_name, args)
        self._baselogdir = os.path.join(State().TEST_WORKING_DIR, "userenum")
        os.makedirs(self._baselogdir, exist_ok=True)
        self._usehostinlogdir = False
        self._users = None
        self._userfile = os.path.join(self._baselogdir, "users.txt")
        self._groups = None
        self._groupsfile = os.path.join(self._baselogdir, "groups.txt")
        
    def _load_users(self):
        self._users = []
        if os.path.exists(self._userfile):
            with State().userenumlock:
                with open(self._userfile , "r") as f:
                    self._users = f.readlines()
    
    def _write_users(self):
        logger.info("Writing %s users in file %s",  len(self._users), self._userfile)
        with State().userenumlock:
            with open(self._userfile , "w") as f:
                f.write(os.linesep.join(self._users))
            
    def add_users(self, users = []):
        if not self._users:
            self._load_users()
        for user in users:
            user = user.strip()
            if not user:
                continue
            if "@" in user:
                user = user.split("@")[0]
            if user not in self._users:
                logger.debug("Adding known user %s", user)
                self._users.append(user)
        self._users = list(set([x.strip() for x in self._users if x]))
        self._write_users()
        
    def _load_groups(self):
        self._groups = []
        if os.path.exists(self._groupsfile):
            with State().userenumlock:
                with open(self._groupsfile , "r") as f:
                    self._groups = f.readlines()
    
    def _write_groups(self):
        logger.info("Writing %s groups in file %s", len(self._groups), self._groupsfile )
        with State().userenumlock:
            with open(self._groupsfile , "w") as f:
                f.write(os.linesep.join(self._groups))
            
    def add_groups(self, groups = []):
        if not self._groups:
            self._load_groups()
        for group in groups:
            group = group.strip()
            if not group:
                continue
            if group not in self._groups:
                logger.debug("Adding known group %s", group)
                self._groups.append(group)
        self._groups = list(set([x.strip() for x in self._groups if x]))
        self._write_groups()
        