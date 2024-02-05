from abc import abstractmethod, ABC
from .config import MAX_LIST_SIZE, WEB_WORDLISTS_FILES_HASEXT
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


    def get_list_priority(self, wordlistfile, extensions = None):
        with open(wordlistfile, 'r') as fp:
            cnt = len(fp.readlines())
        if MAX_LIST_SIZE and cnt >= MAX_LIST_SIZE:
            return -1
        if extensions:
            extcnt = len(extensions.split(","))
            if wordlistfile in WEB_WORDLISTS_FILES_HASEXT and not WEB_WORDLISTS_FILES_HASEXT[wordlistfile]:
                logger.debug("Counting lines in file %s times extensions %s", wordlistfile, extcnt)
                cnt *= extcnt
            
        return int(cnt/1000) + 250 # + 250 to run after NMAPs / NetExec Tests
