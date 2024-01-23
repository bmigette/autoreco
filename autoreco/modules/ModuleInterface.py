from abc import ABC, abstractmethod
from ..logger import logger
from ..state import WORKING_DIR, TEST_DATE, TEST_DATE_STR, datelock
from ..config import DEFAULT_PROCESS_TIMEOUT
import os
from subprocess import STDOUT, check_output
import shlex
from ..TestHost import TestHost
import re

class ModuleInterface(ABC):
    
    
    def __init__(self, testid, target, module_name, args = {}):
        self.status = "notstarted"
        self.args = args
        self.testid = testid
        self.target = target
        self.module_name = module_name

    def get_host_obj(self, ip: str):
        return TestHost(ip)
    
    def get_system_cmd_outptut(self, command: str, timeout: int = DEFAULT_PROCESS_TIMEOUT):
        """Run a system command and get the output

        Args:
            command (str): command line
            timeout (int, optional): Process timeout. Defaults to DEFAULT_PROCESS_TIMEOUT.

        Returns:
            str: command output
        """
        if not isinstance(command, list):
            command = shlex.split(command)
        logger.debug("Executing command %s in module %s...", command, self.module_name)
        ret = check_output(command, stderr=STDOUT, timeout=timeout)
        if type(ret).__name__ == "bytes":
            ret = ret.decode("utf-8")
        logger.debug("Output: %s", ret)
        return ret

    def start(self):
        logger.info("Starting test %s against target %s with module %s", self.testid, self.target, self.module_name )
        try:
            self.status="started"
            self.get_host_obj("discovery").set_test_state(self.testid, self.status, self.module_name, self.target, self.args)
            self.run()
            self.status="done"
        except Exception as e:
            logger.error("Error in test %s against target %s: %s", self.testid, self.target, e, exc_info=True)
            self.status="error"
        finally:
            self.get_host_obj("discovery").set_test_state(self.testid, self.status)
    
    def is_discovery(self):
        return "discovery." in str(self.__class__)
    
    def get_outdir(self):
        global TEST_DATE_STR
        if self.is_discovery():
            h = ""
        else:
            h = self.target if self.target else "" # For global modules
        with datelock:
            datef = f"autoreco_{TEST_DATE_STR}"
        outdir = os.path.join(WORKING_DIR, datef, h)
        if not os.path.isdir(outdir):
            os.makedirs(outdir, exist_ok=True)
        return outdir
    
    def _get_flatten_args(self):
        args = []
        for k, v in self.args.items():
            args.append(re.sub(r'\W+', '', v))
        return "-".join(args)
    
    def get_log_name(self, ext="out"): #TODO Add Timestamp ?
        h = self.target if self.target else "" # For global modules
        outdir = self.get_outdir()
        
        s = ""
        p = ""
        if "service" in self.args:
            s = self.args["service"]
        if "port" in self.args:
            p = self.args["port"]
        args = self._get_flatten_args()
        the_ext = ext
        if the_ext and not the_ext[0] == ".":
            the_ext = "." + the_ext
        filename = f"{self.__class__.__name__}_{h}_{s}_{p}_{args}{the_ext}".replace("/","-").replace(",","-")
        return os.path.join(outdir, filename)

    @abstractmethod
    def run(self):
        pass