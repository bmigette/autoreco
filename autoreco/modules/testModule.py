from .ModuleInterface import ModuleInterface
import time

class testModule(ModuleInterface):
    def run(self):
        time.sleep(2)
        