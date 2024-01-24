import os
import autoreco.state
import autoreco.config
import logging
from datetime import datetime
import json

autoreco.config.LOGLEVEL = logging.DEBUG
autoreco.config.NMAP_DEFAULT_TCP_PORT_OPTION = "--top-ports 10"

autoreco.state.set_working_dir("/tmp/autoreco")

from autoreco.logger import logger


from autoreco.WorkThreader import WorkThreader


# Importing here to make sure we have set config / state properly
from autoreco.TestRunner import TestRunner
runner = TestRunner(hosts=["192.168.158.11"])
runner.run()
# job = {
#         "module_name": "discovery.NetExecDiscovery",
#         "job_id": f"discovery.NetExecDiscovery_192.168.1.0/24_smb",
#         "target": "192.168.1.0/24",
#         "args": {"protocol": "smb"}            
#     }

# WorkThreader.start_threads(None)

# job = {
#         "module_name": "hostscan.NmapHostScan",
#         "job_id": "hostscan.NmapHostScantcp",
#         "target": "192.168.1.252",
#         "args": {"protocol": "tcp"}    
#     }
# WorkThreader.add_job(job)
# WorkThreader.stop_threads()
# with autoreco.state.statelock:
#     logger.debug("State: %s", json.dumps(autoreco.state.TEST_STATE, indent=4))
#     logger.info("="*50)
#     with open(os.path.join(autoreco.state.TEST_WORKING_DIR, "state.json"), "w") as f:
#         f.write(json.dumps(autoreco.state.TEST_STATE, indent=4))

