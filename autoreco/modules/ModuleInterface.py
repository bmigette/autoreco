from abc import ABC, abstractmethod
from ..logger import logger
from ..state import WORKING_DIR
import os
class ModuleInterface(ABC):
    
    
    def __init__(self, testid, target, args = {}):
        self.status = "notstarted"
        self.args = args
        self.testid = testid
        self.target = target

    def start(self):
        logger.info("Starting test %s against target %s with module %s", self.testid, self.target, self.__class__.__name__ )
        try:
            self.status="started"
            self.run()
            self.status="done"
        except Exception as e:
            logger.error("Error in test %s against target %s: %s", self.testid, self.target, e, exc_info=True)
            self.status="error"
    
    def is_discovery(self):
        return "discovery." in str(self.__class__)
    
    def get_outdir(self, discovery = False):
        if self.is_discovery():
            h = ""
        else:
            h = self.target if self.target else "" # For global modules
        outdir = os.path.join(WORKING_DIR, h)
        if not os.path.isdir(outdir):
            os.makedirs(outdir, exist_ok=True)
        return outdir
    
    def get_log_name(self, ext="out"): #TODO Add Timestamp ?
        h = self.target if self.target else "" # For global modules
        outdir = self.get_outdir()
        
        s = ""
        p = ""
        if "service" in self.args:
            s = self.args["service"]
        if "port" in self.args:
            p = self.args["port"]
        the_ext = ext
        if the_ext and not the_ext[0] == ".":
            the_ext = "." + the_ext
        filename = f"{self.__class__.__name__}_{h}_{s}_{p}{the_ext}".replace("/","-")
        return os.path.join(outdir, filename)

    @abstractmethod
    def run(self):
        pass