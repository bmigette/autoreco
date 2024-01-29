from .State import State
import logging
from logging.handlers import RotatingFileHandler

import sys
import os

from .config import FILE_LOGGING, STDOUT_LOGGING, LOGLEVEL



logger = logging.getLogger("autoreco")
logger.setLevel(LOGLEVEL)  

formatter = logging.Formatter(
    '%(asctime)s - %(threadName)s - %(module)s - %(levelname)s - %(message)s')

if STDOUT_LOGGING:
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(LOGLEVEL) 
    handler.setFormatter(formatter)
    logger.addHandler(handler)

if FILE_LOGGING:
        
    handlerfile = RotatingFileHandler(
        os.path.join(State().TEST_WORKING_DIR,  "autoreco.log"), maxBytes=(1024*1024*10), backupCount=7
    )
    handlerfile.setFormatter(formatter)
    handlerfile.setLevel(LOGLEVEL)
    logger.addHandler(handlerfile)


