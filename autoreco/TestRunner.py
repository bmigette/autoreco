from .WorkThreader import WorkThreader
from .logger import logger
import json
import os
from .state import statelock, TEST_STATE, WORKING_DIR
from datetime import datetime

class TestRunner(object):
    def __init__(self, subnet=None, domain=None ):
        self.domain = domain
        self.subnet = subnet
        WorkThreader.start_threads(self.complete_callback)

    def complete_callback(self):
        pass
    
    def host_discovery(self, target):
        job = {
            "module_name": "discovery.NmapSubnetPing",
            "job_id": f"discovery.NmapSubnetPing_{target}",
            "target": target,
            "args": {}            
        }
        WorkThreader.add_job(job)

    def host_scan(self):
        pass

    def run(self):
        try:
            logger.info("="*50)
            logger.info("Tests Started at %s", datetime.now().isoformat())
            logger.info("="*50)
            if self.subnet:
                self.host_discovery(self.subnet)
            self.host_scan()
            
        except Exception as e:
            logger.error("Error in Test Runner: %s", e, exc_info=True)
        finally:            
            WorkThreader.stop_threads()
            
            logger.info("="*50)
            logger.info("Tests Complete at %s", datetime.now().isoformat())
            logger.info("="*50)

            with statelock:
                logger.debug("State: %s", json.dumps(TEST_STATE, indent=4))
                logger.info("="*50)
                with open(os.path.join(WORKING_DIR, "state.json"), "w") as f:
                    f.write(json.dumps(TEST_STATE, indent=4))