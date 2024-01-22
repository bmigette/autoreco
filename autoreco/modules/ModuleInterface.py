from abc import ABC, abstractmethod
from ..logger import logger

class ModuleInterface(ABC):
    def __init__(self, testid, host, args = {}):
        self.status = "notstarted"
        self.args = args
        self.testid = testid
        self.host = host

    def start(self):
        logger.info("Starting test %s against host %s with module %s", self.testid, self.host, self.__class__.__name__ )
        try:
            self.status="started"
            self.run()
            self.status="done"
        except Exception as e:
            logger.error("Error in test %s against host %s: %s", self.testid, self.host, e, exc_info=True)
            self.status="error"

    @abstractmethod
    def run(self):
        pass