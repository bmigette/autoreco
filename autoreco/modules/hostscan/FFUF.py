from ..ModuleInterface import ModuleInterface
from ...logger import logger

from ...TestHost import TestHost


class FFUF(ModuleInterface): # TODO: Support custom host via custom header
    """Class to run FFUF against a single host"""

    def run(self):
        pass
    #Using GoBuster for everything as of now
