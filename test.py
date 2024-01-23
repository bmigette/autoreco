import os
import autoreco.state
import autoreco.config
import logging
from datetime import datetime

autoreco.config.LOGLEVEL = logging.DEBUG

autoreco.state.WORKING_DIR  = "/tmp/autoreco"
autoreco.state.TEST_DATE = datetime.now()
autoreco.state.TEST_DATE_STR = autoreco.state.TEST_DATE.strftime("%Y_%m_%d__%H_%M_%S")
from autoreco.logger import logger


from autoreco.WorkThreader import WorkThreader


# Importing here to make sure we have set config / state properly
from autoreco.TestRunner import TestRunner
runner = TestRunner("192.168.1.0/24", None)
runner.run()
# job = {
#         "module_name": "discovery.NetExecDiscovery",
#         "job_id": f"discovery.NetExecDiscovery_192.168.1.0/24_smb",
#         "target": "192.168.1.0/24",
#         "args": {"protocol": "smb"}            
#     }
# WorkThreader.add_job(job)
# WorkThreader.stop_threads()
