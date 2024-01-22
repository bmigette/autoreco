import os
import autoreco.state
import autoreco.config
import logging
autoreco.config.LOGLEVEL = logging.DEBUG

autoreco.state.WORKING_DIR  = "/tmp/autoreco"
from autoreco.logger import logger


from autoreco.WorkThreader import WorkThreader


# Importing here to make sure we have set config / state properly
from autoreco.TestRunner import TestRunner
runner = TestRunner("192.168.1.0/24", None)
runner.run()
