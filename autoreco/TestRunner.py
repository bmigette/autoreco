from .WorkThreader import WorkThreader
from .HostTestEvaluator import HostTestEvaluator
from .TestHost import TestHost
from .logger import logger
from .utils import print_summary
import json
import os
from .state import statelock, domainlock, KNOWN_DOMAINS, TEST_STATE, TEST_WORKING_DIR
from .config import NETEXEC_DISCOVERY_PROTOCOLS
from datetime import datetime


class TestRunner(object):
    """Class responsible to run tests, stop threads, etc..."""

    def __init__(self, subnet=None, domains=[], hosts=[]):
        self.domains = domains
        self.subnet = subnet
        self.hosts = hosts
        if len(domains) > 0:
            with domainlock:
                KNOWN_DOMAINS = domains.copy()
                
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
                    pass
                else:
                    logger.info(
                        "Adding new job for host %s: \n %s",
                        host,
                        json.dumps(payload, indent=4),
                    )
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
            "args": {},
        }
        WorkThreader.add_job(job)
        for proto in NETEXEC_DISCOVERY_PROTOCOLS:
            job = {
                "module_name": "discovery.NetExecDiscovery",
                "job_id": f"discovery.NetExecDiscovery_{target}_{proto}",
                "target": target,
                "args": {"protocol": proto},
            }
            WorkThreader.add_job(job)

    def host_scan(self, host_ip):
        if not TestHost.is_ip(host_ip):
            raise Exception("Only IP supported as of now")
        h = TestHost(host_ip)  # Will create empty host in state
        self.complete_callback()
        
    def domain_discovery(self, domain):
        # TODO: Implement
        pass

    def print_state(self):
        with statelock:
            logger.debug("State: %s", json.dumps(TEST_STATE, indent=4))
            logger.info("=" * 50)
            
    def run(self, resume = False):
        try:
            logger.info("=" * 50)
            logger.info("Tests Started at %s", datetime.now().isoformat())
            logger.info("Output Dir: %s", TEST_WORKING_DIR)
            logger.info("=" * 50)
            if not resume:
                if self.subnet:
                    self.host_discovery(self.subnet)
            # not used atm, host scan triggered after discovery
            if self.hosts:
                for host in self.hosts:
                    self.host_scan(host)
                    
            if self.domains:
                for d in self.domains:
                    self.domain_discovery(d)
            if resume and len(self.hosts) < 1:
                self.complete_callback()
        except Exception as e:
            logger.error("Error in Test Runner: %s", e, exc_info=True)
            WorkThreader.stop_threads()

    def finish(self):
        logger.info("=" * 50)
        logger.info("Tests Complete at %s", datetime.now().isoformat())
        logger.info("=" * 50)

        self.print_state()

        print_summary()

    
