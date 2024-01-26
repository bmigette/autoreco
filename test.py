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
from autoreco.utils import print_summary

from autoreco.WorkThreader import WorkThreader


# Importing here to make sure we have set config / state properly
from autoreco.TestRunner import TestRunner
#runner = TestRunner(hosts=["192.168.158.11"])
#runner = TestRunner("192.168.199.0/24")
#runner.run()
w = "/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt"
job = {         
        "module_name": "hostscan.FFUF",
        "job_id": "testFFUF",
        "target": "192.168.209.15",
        "args": {
            "url": f"http://192.168.209.15:8080",
            "mode": "vhost",
            "domain": "test.com",
            "wordlist": w,
        }
}

WorkThreader.start_threads(None)

# job = {
#         "module_name": "hostscan.NmapHostScan",
#         "job_id": "hostscan.NmapHostScantcp",
#         "target": "192.168.1.252",
#         "args": {"protocol": "tcp"}    
#     }
WorkThreader.add_job(job)
WorkThreader.stop_threads()
print_summary()
# with autoreco.state.statelock:
#     logger.debug("State: %s", json.dumps(autoreco.state.TEST_STATE, indent=4))
#     logger.info("="*50)
#     with open(os.path.join(autoreco.state.TEST_WORKING_DIR, "state.json"), "w") as f:
#         f.write(json.dumps(autoreco.state.TEST_STATE, indent=4))

