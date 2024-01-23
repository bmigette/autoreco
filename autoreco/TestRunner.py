from .WorkThreader import WorkThreader
from .HostTestEvaluator import HostTestEvaluator
from .TestHost import TestHost
from .logger import logger
import json
import os
from .state import statelock, TEST_STATE, WORKING_DIR
from .config import NETEXEC_DISCOVERY_PROTOCOLS
from datetime import datetime

class TestRunner(object):
    def __init__(self, subnet=None, domain=None, host=None ):

        self.domain = domain
        self.subnet = subnet
        self.host = host
        WorkThreader.start_threads(self.complete_callback)

    def complete_callback(self):
        logger.debug("Entering Complete Callback")
        with statelock:
            state = TEST_STATE.copy()
        for k, v in state.items():
            if k == "discovery": 
                continue
            host = TestHost(k)
            evaluator = HostTestEvaluator(host)
            tests = evaluator.get_tests()
            for testid, payload in tests.items():
                if host.has_test(testid):
                    logger.debug("Skipping test %s", testid) # TODO Remove
                else:
                    logger.info("Adding new job for host %s: \n %s", host, json.dumps(payload, indent=4))
                    host.set_test_state(testid, "queued")
                    WorkThreader.add_job(payload)
        if WorkThreader.finished():
            WorkThreader.stop_threads()
            self.finish()
        
    
    def host_discovery(self, target):
        job = {
            "module_name": "discovery.NmapSubnetPing",
            "job_id": f"discovery.NmapSubnetPing_{target}",
            "target": target,
            "args": {}            
        }
        WorkThreader.add_job(job)
        for proto in NETEXEC_DISCOVERY_PROTOCOLS:
            job = {
                "module_name": "discovery.NetExecDiscovery",
                "job_id": f"discovery.NetExecDiscovery_{target}_{proto}",
                "target": target,
                "args": {"protocol": proto}            
            }
            WorkThreader.add_job(job)
            
    def host_scan(self, host_ip):
        if not TestHost.is_ip(host_ip):
            raise Exception("Only IP supported as of now")
        h = TestHost(host_ip) #Will create empty host in state
        self.complete_callback()
    
    def print_state(self):
        with statelock:
            logger.debug("State: %s", json.dumps(TEST_STATE, indent=4))
            logger.info("="*50)
            with open(os.path.join(WORKING_DIR, "state.json"), "w") as f:
                f.write(json.dumps(TEST_STATE, indent=4))

    def run(self):
        try:
            logger.info("="*50)
            logger.info("Tests Started at %s", datetime.now().isoformat())
            logger.info("="*50)
            if self.subnet:
                self.host_discovery(self.subnet)
            # not used atm, host scan triggered after discovery
            if self.host:
                self.host_scan(self.host)
            
        except Exception as e:
            logger.error("Error in Test Runner: %s", e, exc_info=True)

            
    def finish(self):
        logger.info("="*50)
        logger.info("Tests Complete at %s", datetime.now().isoformat())
        logger.info("="*50)

        self.print_state()
        
        self.print_summary()
                    
    def print_summary(self):
        total_tests = 0
        total_hosts = 0
        success_tests = 0
        failed_tests = 0
        with statelock:
            for host, data in TEST_STATE.items():
                total_hosts += 1
                if "tests_state" in data:
                    for testid, testdata in data["tests_state"].items():
                        total_tests += 1
                        if testdata["state"] == "done":
                            success_tests += 1
                        elif testdata["state"] == "error":
                            failed_tests += 1
                        else:
                            logger.warn("Test %s state: %s", testid, testdata["state"])
                            
            logger.info("="*50)
            logger.info("# Ran %s Tests against %s hosts", total_tests, total_hosts)
            logger.info("# Success: %s, Failed: %s", success_tests, failed_tests)
            logger.info("="*50)