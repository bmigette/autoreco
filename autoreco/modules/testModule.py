from .ModuleInterface import ModuleInterface
import time


class testModule(ModuleInterface):
    """Dump Module"""

    def run(self):
        time.sleep(2)
