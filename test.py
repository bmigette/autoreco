import autoreco.State
autoreco.State.State().set_working_dir("/tmp/autoreco")

from autoreco.TestRunner import TestRunner
from autoreco.HostTestEvaluator import HostTestEvaluator
from autoreco.WorkThreader import WorkThreader
from autoreco.utils import print_summary
from autoreco.logger import logger
import os

import autoreco.config
import logging
from datetime import datetime
import json

autoreco.config.STDOUT_LOGLEVEL = logging.DEBUG
autoreco.config.WATCHDOG_INTERVAL = 30
autoreco.config.NMAP_DEFAULT_TCP_PORT_OPTION = "--top-ports 10"


from autoreco.TestHost import TestHost


# Importing here to make sure we have set config / state properly
# autoreco.State.State().set_working_dir("/home/babadmin/offsec/challenges/challenge2_relia/autoreco_2024_02_05__13_30_58", resume=True)
# autoreco.State.State().load_state()

runner = TestRunner()
# runner.move_empty_log_files()
WorkThreader.start_threads(None)
# runner = TestRunner("192.168.230.0/24")
# runner.run()
job = {"job_id": "userenum.NetExecRIDBrute_172.16.230.10_ridbrute_joe_b43194e1fddd43dcab8b627e298aef89",
       "state": "done",
       "module_name": "userenum.NetExecRIDBrute",
       "target": "172.16.230.10",
       "args": {
           "user": "joe",
           "password": "Flowers1"
       },
       "priority": 150
       }
WorkThreader.add_job(job)

job = {"job_id": "userenum.NetExecUserEnum_172.16.230.10_netexec_smb_groups_joe_b43194e1fddd43dcab8b627e298aef89",
       "state": "done",
       "module_name": "userenum.NetExecUserEnum",
       "target": "172.16.230.10",
       "args": {
           "action": "groups",
           "protocol": "smb",
                       "user": "joe",
           "password": "Flowers1",
           "pmode": "pw",
                    "target": "172.16.230.10"
       },
       "priority": 100
       }
WorkThreader.add_job(job)

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
#  WorkThreader.add_job(job)

# WorkThreader.start_threads(None)

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
