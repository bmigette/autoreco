
import threading
import os
from datetime import datetime
import json

"""
State module. The variables below are global to the scope of the script
"""

"""
Accessing below variable should always get the statelock first
ex:
with state.statelock:
    pass
    
See https://superfastpython.com/lock-an-object-in-python/#Lock_an_Object
"""

class SingletonMeta(type):
    """
    The Singleton class can be implemented in different ways in Python. Some
    possible methods include: base class, decorator, metaclass. We will use the
    metaclass because it is best suited for this purpose.
    """

    _instances = {}

    def __call__(cls, *args, **kwargs):
        """
        Possible changes to the value of the `__init__` argument do not affect
        the returned instance.
        """
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class State(metaclass=SingletonMeta):
    """This class provide a thread safe access to a singleton state
    """
    def __init__(self):   
        # External Locks
        self.statelock = threading.Lock()
        self.domainlock = threading.Lock()
        self.userenumlock = threading.Lock()
        # Internal Locks
        self._statelock = threading.Lock()
        self._domainlock = threading.Lock()
        self._runtimelock = threading.Lock()
        self._iplock = threading.Lock()
        self._TEST_STATE = {}
        self._KNOWN_DOMAINS = []
        self._RUNTIME = {}
        self.TEST_DATE = None
        self.TEST_DATE_STR = None
        self.WORKING_DIR = None
        self.TEST_WORKING_DIR = None  
   
    def set_working_dir(self, dir, nocreate = False, resume = False): 
        """Set the working directory, and creates it if does not exists
        """       
        if not resume:
            self.WORKING_DIR = dir
            self.TEST_DATE = datetime.now()
            self.TEST_DATE_STR = self.TEST_DATE.strftime("%Y_%m_%d__%H_%M_%S")
            self.TEST_WORKING_DIR = os.path.join(self.WORKING_DIR, f"autoreco_{self.TEST_DATE_STR}")
            if not nocreate:
                os.makedirs(self.TEST_WORKING_DIR, exist_ok=True)
        else:
            self.TEST_WORKING_DIR = dir
            self.WORKING_DIR = os.path.abspath(os.path.join(self.TEST_WORKING_DIR, os.pardir))
            self.TEST_DATE_STR = self.TEST_WORKING_DIR.split("autoreco_")[1].replace("/", "")      
    
    def write_host_ips_to_disk(self):
        """Write known IPs to the disk. 
        This will write everytime a test is complete because of callback. Not optimized but should work
        """
        from .utils import is_ip
        with self._iplock:
            state = self.TEST_STATE.copy()
            ips = [k for k, _ in state.items() if is_ip(k)]
            with open(os.path.join(self.TEST_WORKING_DIR, "ips.txt"), "w") as f:
                f.write(os.linesep.join(ips))
    
    @property
    def TEST_STATE(self):
        with self._statelock:
            return self._TEST_STATE
        
    @TEST_STATE.setter
    def TEST_STATE(self, value):
        with self._statelock:
            self._TEST_STATE = value.copy()
    
    @property
    def KNOWN_DOMAINS(self):
        with self._domainlock:
            return self._KNOWN_DOMAINS
        
    @KNOWN_DOMAINS.setter
    def KNOWN_DOMAINS(self, value):
        with self._domainlock:
            self._KNOWN_DOMAINS = value.copy()
            
    @property
    def RUNTIME(self):
        with self._runtimelock:
            return self._RUNTIME
        
    @RUNTIME.setter
    def RUNTIME(self, value):
        with self._runtimelock:
            self.RUNTIME = value.copy()
            
    def load_state(self):
        with self._statelock:
            with open(os.path.join(self.TEST_WORKING_DIR, "state.json")) as f:
                self._TEST_STATE = json.loads(f.read())
        with self._domainlock:
            with open(os.path.join(self.TEST_WORKING_DIR, "domains.json")) as f:
                self._KNOWN_DOMAINS = json.loads(f.read())