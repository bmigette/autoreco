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
autoreco.State.State().set_working_dir("/home/babadmin/offsec/challenges/challenge3_skylark/10.10_scan/autoreco_2024_03_14__19_10_59", resume=True)
autoreco.State.State().load_state()

h = TestHost("10.10.137.250")
eval = HostTestEvaluator(h)
eval.get_ad_dc_ips()

# runner = TestRunner()
# runner.move_empty_log_files()
# WorkThreader.start_threads(None)
# runner = TestRunner("192.168.230.0/24")
# runner.run()
# job = {
#     "module_name": "discovery.NmapSubnetDiscovery",
#     "job_id": "discovery.NmapSubnetDiscoveryQuickScan_192.168.188.0_24",
#     "target": "192.168.188.189 192.168.188.18",
#     "priority": 100,
#     "args": {
#         "ports": "--top-ports 50"
#     }
# }
# WorkThreader.add_job(job)


w = "/usr/share/seclists/Discovery/Web-Content/big.txt"

job = {
        "module_name": "hostscan.FeroxBuster",
        "job_id": "FeroxBuster",
        "target": "192.168.188.245",
        "priority": 100,
        "args": {
            "url": f"http://192.168.188.245:80",
            "mode": "dir",
            "wordlist": w,
        }
}
# WorkThreader.add_job(job)

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
