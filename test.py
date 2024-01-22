import os
import autoreco.state
autoreco.state.WORKING_DIR  = os.getcwd()
from autoreco.logger import logger

from autoreco.WorkThreader import WorkThreader



WorkThreader.start_threads(None)
for i in range(0,20):
    WorkThreader.add_job({
    "module_name": "testModule",
    "job_id":f"test{i}",
    "target":f"target{i}",
    "args": {}
})
    
WorkThreader.queue.join()
logger.info('All work completed')
WorkThreader.stop_threads()