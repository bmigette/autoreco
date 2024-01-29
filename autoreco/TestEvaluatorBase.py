from abc import abstractmethod, ABC
from .config import MAX_LIST_SIZE
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
        if MAX_LIST_SIZE and cnt >= MAX_LIST_SIZE:
            return -1
        return int(cnt/1000)
