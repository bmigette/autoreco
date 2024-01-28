from abc import abstractmethod, ABC
from .state import domainlock, KNOWN_DOMAINS, statelock, TEST_STATE
from .config import WEB_WORDLISTS, GOBUSTER_FILE_EXT, USERENUM_LISTS
from .logger import logger

import re

class TestEvaluatorBase(ABC):

    @abstractmethod
    def get_tests(self):
        #to override
        pass
    
    def _safe_merge(self, d1, d2):
        tempd = d1.copy()
        for k, v in d2.items():
            if k in tempd:
                raise Exception(f"{k} is already in dict")
            tempd[k] = v
        return tempd


    def get_list_priority(self, wordlistfile):
        with open(wordlistfile, 'r') as fp:
            cnt = len(fp.readlines())
        return int(cnt/1000)
