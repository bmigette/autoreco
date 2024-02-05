from .State import State
import logging
from logging.handlers import RotatingFileHandler

import sys
import os

from .config import FILE_LOGGING, STDOUT_LOGGING, STDOUT_LOGLEVEL, FILE_LOGGING_DEBUG



logger = logging.getLogger("autoreco")
logger.setLevel(logging.DEBUG)  # Setting this to debug for file debug

formatter = logging.Formatter(
    '%(asctime)s - %(threadName)s - %(module)s - %(levelname)s - %(message)s')

if STDOUT_LOGGING:
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(STDOUT_LOGLEVEL) 
    handler.setFormatter(formatter)
    logger.addHandler(handler)

if FILE_LOGGING:
        
    handlerfile = RotatingFileHandler(
        os.path.join(State().TEST_WORKING_DIR,  "autoreco.log"), maxBytes=(1024*1024*10), backupCount=7
    )
    handlerfile.setFormatter(formatter)
    handlerfile.setLevel(STDOUT_LOGLEVEL)
    logger.addHandler(handlerfile)
    
    handlerfileerr = RotatingFileHandler(
        os.path.join(State().TEST_WORKING_DIR,  "autoreco.error.log"), maxBytes=(1024*1024*10), backupCount=7
    )
    handlerfileerr.setFormatter(formatter)
    handlerfileerr.setLevel(logging.ERROR)
    logger.addHandler(handlerfileerr)

    if FILE_LOGGING_DEBUG:
        handlerfiledebug = RotatingFileHandler(
            os.path.join(State().TEST_WORKING_DIR,  "autoreco.debug.log"), maxBytes=(1024*1024*10), backupCount=7
        )
        handlerfiledebug.setFormatter(formatter)
        handlerfiledebug.setLevel(logging.DEBUG)
        logger.addHandler(handlerfiledebug)

