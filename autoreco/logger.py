from .state import WORKING_DIR
import logging
from logging.handlers import RotatingFileHandler

import sys
import os

from .config import FILE_LOGGING, STDOUT_LOGGING



logger = logging.getLogger("autoreco")
logger.setLevel(logging.DEBUG)  

formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(module)s - %(levelname)s - %(message)s')

if STDOUT_LOGGING:
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG ) 
    handler.setFormatter(formatter)
    logger.addHandler(handler)

if FILE_LOGGING:
        
    handlerfile = RotatingFileHandler(
        os.path.join(WORKING_DIR,  "autoreco.log"), maxBytes=(1024*1024*10), backupCount=7
    )
    handlerfile.setFormatter(formatter)
    handlerfile.setLevel(logging.DEBUG)
    logger.addHandler(handlerfile)


