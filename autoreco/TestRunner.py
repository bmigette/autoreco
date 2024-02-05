from .WorkThreader import WorkThreader
from .HostTestEvaluator import HostTestEvaluator

from .TestHost import TestHost
from .logger import logger
from .utils import print_summary, is_ip
import json
import os
from .State import State
from .config import NETEXEC_DISCOVERY_PROTOCOLS
from datetime import datetime


class TestRunner(object):
    """Class responsible to run tests, stop threads, etc..."""

    def stop_signal_handler(sig, frame):
        """CTRL+C Signal Handler

        Args:
            sig (_type_): _description_
            frame (_type_): _description_
        """
        WorkThreader.stop_threads()

    def __init__(self, subnet=None, domains=[], hosts=[]):
        logger.debug("Starting TestRunner with args: %s, %s, %s",
                     subnet, domains, hosts)
        self.domains = domains
        self.subnet = subnet
        self.hosts = hosts
        self.finishing = False
        if len(domains) > 0:
            State().KNOWN_DOMAINS = domains  # Copy is handled by state file

        WorkThreader.start_threads(self.complete_callback)
        self.set_handler()

    def complete_callback(self):
        """Callback function when a job is complete, will check if additional jobs needs to be scheduled
        """
        logger.debug("Entering Complete Callback")
        try:
            state = State().TEST_STATE.copy()
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
                        if "job_id" not in payload:  # Should not happen unless there's an Error in HostTestEvaluator
                            logger.warn("No job_id in payload %s", payload)
                            payload["job_id"] = testid
                        logger.info(
                            "Adding new job for host %s with module %s on target %s",
                            host,
                            payload["module_name"],
                            payload["target"]
                        )
                        logger.debug(
                            "Job Payload: \n %s",
                            json.dumps(payload, indent=4)
                        )
                        args = payload["args"] if "args" in payload else {}
                        priority =  payload["priority"] if "priority" in payload else None
                        host.set_test_state(
                            testid, "queued", payload["module_name"], payload["target"], args, priority)
                        WorkThreader.add_job(payload)
        except Exception as e:
            logger.error("Exception in Complete Callback: %s",
                         e, exc_info=True)
        finally:
            if WorkThreader.finished():
                WorkThreader.stop_threads()
                self.finish()

    def set_handler(self):
        """Sets CTRL+C Handler
        """
        import signal
        signal.signal(signal.SIGINT, TestRunner.stop_signal_handler)

    def host_discovery(self, target):
        """Start host discovery process against a subnet

        Args:
            target (str): Subnet, exemple: 192.168.1.0/24
        """
        global NETEXEC_DISCOVERY_PROTOCOLS
        job = {
            "module_name": "discovery.NmapSubnetPing",
            "job_id": f"discovery.NmapSubnetPing_{target}",
            "target": target,
            "priority": 10,
            "args": {},
        }
        WorkThreader.add_job(job)
        for proto in NETEXEC_DISCOVERY_PROTOCOLS:
            job = {
                "module_name": "discovery.NetExecDiscovery",
                "job_id": f"discovery.NetExecDiscovery_{target}_{proto}",
                "target": target,
                "priority": 10,
                "args": {"protocol": proto},
            }
            WorkThreader.add_job(job)

    def host_scan(self, host_ip):
        """Initiate a single host scan

        Args:
            host_ip (str): IP address

        Raises:
            Exception: Invalid host_ip
        """
        if not is_ip(host_ip):
            raise Exception("Only IP supported as of now")
        h = TestHost(host_ip)  # Will create empty host in state
        self.complete_callback()

    def resume_failed(self):
        """Resume failed test
        """
        state = State().TEST_STATE.copy()  #  Use Lock and double state
        from copy import deepcopy
        # Can't modify a dict in a loop it seems ...
        targetstate = deepcopy(state)
        with State().statelock:
            for k in state.keys():
                if k == "discovery":
                    continue
                for testname, testdata in state[k]["tests_state"].items():
                    if testdata["state"] not in  ["done", "ignored"]:
                        targetstate[k]["tests_state"].pop(testname)
                        # Deleting will force test suggestor to resume
        State().TEST_STATE = targetstate

    def print_state(self):
        """Display test state
        """

        logger.debug("State: %s", json.dumps(State().TEST_STATE, indent=4))
        logger.debug("=" * 50)

    def run(self, resume=False, resume_failed=True):
        """Run the tets

        Args:
            resume (bool, optional): Whether we resume an existing tests. Defaults to False.
            resume_failed (bool, optional): Whether we should retry failed/stopped tests in resume. Defaults to True.
        """
        try:
            logger.info("=" * 50)
            if resume:
                logger.info("Tests Resumed at %s", datetime.now().isoformat())
                if resume_failed:
                    self.resume_failed()
            else:
                logger.info("Tests Started at %s", datetime.now().isoformat())
            logger.info("Output Dir: %s", State().TEST_WORKING_DIR)
            logger.info("=" * 50)
            if not resume:
                if self.subnet:
                    self.host_discovery(self.subnet)
            # not used atm, host scan triggered after discovery
            if self.hosts:
                for host in self.hosts:
                    self.host_scan(host)

            if resume and len(self.hosts) < 1:
                self.complete_callback()

        except Exception as e:
            logger.error("Error in Test Runner: %s", e, exc_info=True)
            WorkThreader.stop_threads()

    def move_empty_log_files(self):
        """Move empty log files + files associated to empty_logs folder
        """
        import glob
        import shutil
        for folder in os.walk(State().TEST_WORKING_DIR):
            folder = folder[0]
            if "empty_logs" in folder:
                continue
            outdir = os.path.join(folder, "empty_logs")
            for file in glob.glob(os.path.join(folder, "*.log")):
                file_stats = os.stat(file)
                if file_stats.st_size == 0:
                    try:
                        if os.path.exists(file.replace(".log", ".cmd.err")):
                            logger.debug(
                                "Not Moving empty file because .cmd.err exits: %s", file)
                            continue
                        if not os.path.isdir(outdir):
                            os.makedirs(outdir, exist_ok=True)
                        for file_to_move in glob.glob(file.replace(".log", ".*")):
                            logger.debug("Moving empty file %s", file_to_move)
                            shutil.move(file_to_move, outdir)
                    except Exception as e:
                        logger.error("Error when moving file %s: %s", file, e)

    def finish(self):
        if self.finishing:
            return
        self.finishing = True
        logger.info("=" * 50)
        logger.info("Tests Complete at %s", datetime.now().isoformat())
        logger.info("=" * 50)

        self.print_state()

        print_summary()
        self.move_empty_log_files()
