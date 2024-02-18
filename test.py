import os
import autoreco.State
import autoreco.config
import logging
from datetime import datetime
import json

autoreco.config.STDOUT_LOGLEVEL = logging.DEBUG
autoreco.config.WATCHDOG_INTERVAL = 30
autoreco.config.NMAP_DEFAULT_TCP_PORT_OPTION = "--top-ports 10"

autoreco.State.State().set_working_dir("/tmp/autoreco")
from autoreco.logger import logger
from autoreco.utils import print_summary

from autoreco.WorkThreader import WorkThreader
from autoreco.HostTestEvaluator import HostTestEvaluator
from autoreco.TestHost import TestHost

# Importing here to make sure we have set config / state properly
from autoreco.TestRunner import TestRunner
#autoreco.State.State().set_working_dir("/home/babadmin/offsec/challenges/challenge2_relia/autoreco_2024_02_05__13_30_58", resume=True)
#autoreco.State.State().load_state()

runner = TestRunner()
runner.move_empty_log_files()

runner = TestRunner("192.168.230.0/24")
runner.run()
# w = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
# job = {         
#         "module_name": "hostscan.FFUF",
#         "job_id": "testFFUF",
#         "target": "192.168.229.213",
#         "args": {
#             "url": f"http://192.168.229.213:20000",
#             "mode": "vhost",
#             "domain": "test.com",
#             "wordlist": w,
#         }
# }
# WorkThreader.add_job(job)

# w = "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
# job = {         
#         "module_name": "hostscan.GoBuster",
#         "job_id": "testGoBuster",
#         "target": "192.168.229.213",
#         "args": {
#             "url": f"http://192.168.229.213:20000",
#             "mode": "dir",
#             "wordlist": w,
#         }
# }
# WorkThreader.add_job(job)

#WorkThreader.start_threads(None)

# job = {
#         "module_name": "hostscan.NmapHostScan",
#         "job_id": "hostscan.NmapHostScantcp",
#         "target": "192.168.1.252",
#         "args": {"protocol": "tcp"}    
#     }
print_summary()

#     logger.debug("State: %s", json.dumps(autoreco.State.State().TEST_STATE, indent=4))
#     logger.info("="*50)
#     with open(os.path.join(autoreco.State.State().TEST_WORKING_DIR, "state.json"), "w") as f:
#         f.write(json.dumps(autoreco.State.State().TEST_STATE, indent=4))

