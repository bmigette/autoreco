from threading import Thread
from threading import Event
from queue import PriorityQueue, Empty
from .TestHost import TestHost
from .TestJob import TestJob
from .logger import logger
from .config import (
    NUM_THREADS,
    QUEUE_SIZE,
    QUEUE_WAIT_TIME,
    TEST_FILTERS,
    WATCHDOG_INTERVAL,
    WATCHDOG_SLEEP_INTERVAL,
)
from .modules.ModuleLoader import ModuleLoader
from .state import statelock, TEST_STATE, TEST_WORKING_DIR, domainlock, KNOWN_DOMAINS
from .utils import print_summary
from datetime import datetime
import fnmatch
import os
import json
import time

"""
Job Syntax:
"""
JOB_TEMPLATE = {"module_name": "", "job_id": "", "target": "", "args": {}}


class Watchdog:
    """Class to regularly save state and print thread status"""

    def __init__(self):
        self.stopevent = Event()
        self.thread = Thread(target=self.watch, args=(self.stopevent,))
        self.thread.start()

    def watch(self, stopevent) -> None:
        last_date = datetime.now()
        last_loop_date = datetime.now()
        while not stopevent.is_set():
            try:
                last_date = datetime.now()
                if abs(
                    (last_date - last_loop_date).total_seconds() > WATCHDOG_INTERVAL
                ):
                    last_loop_date = last_date
                    self.print_thread_stats()
                    print_summary()
                    self.write_state()
            except Exception as e:
                logger.error("Error in watchdog: %s", e, exc_info=True)
            time.sleep(WATCHDOG_SLEEP_INTERVAL)
        self.write_state()  # Final write on exit

    def stop(self) -> None:
        logger.debug("Stopping Watchdog")
        self.stopevent.set()

    def print_thread_stats(self) -> None:
        try:
            logger.debug("=" * 50)
            logger.debug("| Threads Status:")
            logger.debug("-" * 50)
            for i, inst in WorkThreader._instances.items():
                job = ""
                if inst.current_job:
                    job = (
                        inst.current_job_date.strftime("%H:%M:%S")
                        + ": "
                        + inst.current_job["module_name"]
                        + " / "
                        + inst.current_job["target"]
                        + " / "
                        + str(inst.current_job["args"])
                    )
                    if len(job) > 255:
                        job = job[:255]
                extra_space = " " if inst.busy else ""
                logger.debug(
                    "| Thread %s | Busy %s  %s| %s",
                    inst.thread_id,
                    inst.busy,
                    extra_space,
                    job,
                )
            logger.debug("=" * 50)
        except Exception as e:
            logger.error("Error int print_thread_stats: %s", e, exc_info=True)

    def write_host_summary(self) -> None:
        """Write summary of host to disk
        """
        with statelock:
            state = TEST_STATE.copy()
        with open(os.path.join(TEST_WORKING_DIR, "hostsummary.txt"), "w") as f:
            f.write("="*50 + "\n")
            for k, v in state.items():
                if k == "discovery":
                    continue
                hostobj = TestHost(k)
                services = ",".join(hostobj.services)
                tcp_ports = ",".join(map(str, hostobj.tcp_ports))
                udp_ports = ",".join(map(str, hostobj.udp_ports))
                hostnames = ",".join(hostobj.hostnames)
                f.write(f"Hostname (s): {hostnames}\n")
                f.write(f"Domain: {hostobj.domain}\n")
                f.write(f"services: {services}\n")
                f.write(f"tcp_ports: {tcp_ports}\n")
                f.write(f"udp_ports: {udp_ports}\n")
                f.write("="*50 + "\n")

    def write_state(self) -> None:
        """Write current state to disk
        """
        global KNOWN_DOMAINS, TEST_WORKING_DIR, TEST_STATE
        try:
            with statelock:
                with open(os.path.join(TEST_WORKING_DIR, "state.json"), "w") as f:
                    f.write(json.dumps(TEST_STATE, indent=4))
            with domainlock:
                with open(os.path.join(TEST_WORKING_DIR, "domains.json"), "w") as f:
                    f.write(json.dumps(KNOWN_DOMAINS, indent=4))
            self.write_host_summary()
        except Exception as e:
            logger.error("Error when writing state file: %s", e, exc_info=True)


class _WorkThread:
    """Single thread class. This class is the one picking up jobs from the queue, and executing it with appropriate module"""

    def __init__(self, thread_id: str, queue: PriorityQueue, complete_callback):
        """Constructor

        Args:
            thread_id (str): Thread ID
            queue (Queue): Jobs queue object
            complete_callback (function): Callback to run when a job is complete to trigger changes
        """
        self.thread_id = thread_id
        self.queue = queue
        self.complete_callback = complete_callback
        self.current_job = None
        self.current_job_date = None
        self.modules = ModuleLoader.get_modules()
        self.stopevent = Event()
        self.thread = Thread(target=self.thread_consumer,
                             args=(self.stopevent,))
        self.busy = False
        self.thread.start()

    def stop(self) -> None:
        logger.debug("Stopping thread %s...", self.thread_id)
        self.stopevent.set()

    def process_job(self, job: dict) -> None:
        """Process a queued job

        Args:
            job (ModuleInterface): Job Details

        Raises:
            Exception: Invalid Job Object

        Returns:
            None:
        """
        try:
            # def __init__(self, testid, target, args = {}):
            self.current_job = job
            self.current_job_date = datetime.now()
            self.busy = True
            module_object = self.modules[job["module_name"]](
                job["job_id"], job["target"], job["module_name"], job["args"]
            )
            module_object.start()
        finally:
            self.busy = False
            self.current_job = None
            self.current_job_date = None
            if self.complete_callback:
                try:
                    self.complete_callback()
                except Exception as e:
                    logger.error(
                        "Error in thread callback %s: %s",
                        self.thread_id,
                        e,
                        exc_info=True,
                    )

    def thread_consumer(self, stopevent):
        """The Queue Consumer thread callback function"""
        logger.debug("Consumer Thread %s: Running", self.thread_id)
        # consume items
        while not stopevent.is_set():
            jobget = False
            try:
                priority, job = self.queue.get(timeout=QUEUE_WAIT_TIME)
                jobget = True
                logger.debug("processing job %s (p: %s) ...", job.data, priority)
                self.process_job(job.data)
                logger.debug("processing job %s ... Done", job.data)
            except Empty:
                # This will happen if queue is empty.
                # We use this so that threads are not waiting infinitely on the queue
                # And can get the stop event set.
                pass

            except Exception as e:
                logger.error(
                    "Error happened in Worker Consumer Thread %s: %s",
                    self.thread_id,
                    e,
                    exc_info=True,
                )
            finally:
                if jobget:
                    logger.debug("Task done %s", self.thread_id)
                    self.queue.task_done()
        logger.debug("Stopping thread %s... Done", self.thread_id)


class WorkThreader:
    """Class that manages thread execution and queuing"""

    _instances = {}
    queue = PriorityQueue(QUEUE_SIZE)
    watchdog = None

    def add_job(job: dict) -> None:
        if "priority" not in job:
            logger.warn("Job %s has no priority", job)
            job["priority"] = 100
        job["priority"] = int(job["priority"])
        joboj = TestJob(job["priority"], job)
        if TEST_FILTERS and len(TEST_FILTERS) > 0:
            for filter in TEST_FILTERS:
                if fnmatch.fnmatch(filter.lower(), job["module_name"].lower()):
                    logger.debug("Adding job with data %s", job)
                    WorkThreader.queue.put((job["priority"], joboj))
                    break
            logger.info(
                "Skipping job because does not match filter.Data:\n%s", job)
        else:
            logger.debug("Adding job with data %s", job)
            WorkThreader.queue.put((job["priority"], joboj))
        logger.debug("======== QUEUE SIZE: %s ========",
                     WorkThreader.queue.qsize())

    def start_threads(complete_callback):
        """Start the worker threads

        Args:
            complete_callback (func): Callback notification when a thread is done
        """
        # TODO Handle CTRL+C for gracefull shutdown
        for i in range(0, NUM_THREADS):
            logger.info("Creating Worker thread %s", i)
            WorkThreader._instances[str(i)] = _WorkThread(
                i, WorkThreader.queue, complete_callback
            )
        WorkThreader.watchdog = Watchdog()

    def finished() -> bool:
        """Returns true if all tasks finished

        Returns:
            bool: true if finished, false otherwise
        """
        if not WorkThreader.queue.empty():
            return False
        for i, inst in WorkThreader._instances.items():
            if inst.busy:
                return False

        return True

    def stop_threads() -> None:
        """Stop threads
        """
        logger.info("Stopping threads...")
        WorkThreader.watchdog.stop()
        for i, inst in WorkThreader._instances.items():
            inst.stop()

        for i, inst in WorkThreader._instances.items():
            # inst.thread.join()
            del inst
