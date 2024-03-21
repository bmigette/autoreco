from .ModuleInterface import ModuleInterface
import time


class SleepModule(ModuleInterface):
    """sleep Module"""

    def run(self):
        time.sleep(self.args["sleep"])
