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
from .State import State
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
                    onebusy = self.print_thread_stats()
                    print_summary()
                    self.write_state()
                    if not onebusy:
                        if WorkThreader._callback:
                            WorkThreader._callback()
            except Exception as e:
                logger.error("Error in watchdog: %s", e, exc_info=True)
            time.sleep(WATCHDOG_SLEEP_INTERVAL)
        self.write_state()  # Final write on exit

    def stop(self) -> None:
        logger.debug("Stopping Watchdog")
        self.stopevent.set()

    def print_thread_stats(self) -> None:
        onebusy = False
        try:
            logger.info("=" * 50)
            logger.info("| Threads Status:")
            logger.info("-" * 50)
            
            for i, inst in WorkThreader._instances.items():
                if inst.busy:
                    onebusy = True
                job = ""
                if inst.current_job:
                    progress = inst.get_progress()
                    if progress:
                        progress = " | " + progress
                    else:
                        progress = ""
                    job = (
                        inst.current_job_date.strftime("%H:%M:%S")
                        + ": "
                        + inst.current_job["module_name"]
                        + " | "
                        + inst.current_job["target"]
                        + progress
                        + " | "
                        + str(inst.current_job["args"])
                    )
                    if len(job) > 255:
                        job = job[:255]
                extra_space = " " if inst.busy else ""
                logger.info(
                    "| Thread %s | Busy %s  %s| %s",
                    inst.thread_id,
                    inst.busy,
                    extra_space,
                    job,
                )
            logger.info("=" * 50)
        except Exception as e:
            logger.error("Error int print_thread_stats: %s", e, exc_info=True)
        finally:
            return onebusy

    def write_host_summary(self) -> None:
        """Write summary of host to disk
        """
        state = State().TEST_STATE.copy()
        with open(os.path.join(State().TEST_WORKING_DIR, "hostsummary.txt"), "w") as f:
            f.write("="*50 + "\n")
            for k, v in state.items():
                if k == "discovery":
                    continue
                hostobj = TestHost(k)
                services = ",".join(hostobj.services)
                tcp_ports = ",".join(map(str, hostobj.tcp_ports))
                udp_ports = ",".join(map(str, hostobj.udp_ports))
                hostnames = ",".join(hostobj.hostnames)
                f.write(f"IP: {k}\n")
                f.write(f"Hostname (s): {hostnames}\n")
                f.write(f"Domain: {hostobj.domain}\n")
                f.write(f"services: {services}\n")
                f.write(f"tcp_ports: {tcp_ports}\n")
                f.write(f"udp_ports: {udp_ports}\n")
                f.write("="*50 + "\n")

    def write_state(self) -> None:
        """Write current state to disk
        """
        try:
            with open(os.path.join(State().TEST_WORKING_DIR, "state.json"), "w") as f:
                f.write(json.dumps(State().TEST_STATE, indent=4))
            with open(os.path.join(State().TEST_WORKING_DIR, "domains.json"), "w") as f:
                f.write(json.dumps(State().KNOWN_DOMAINS, indent=4))
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
        self.current_module_obj = None
        self.is_stopping = False
        self.modules = ModuleLoader.get_modules()
        self.stopevent = Event()
        self.thread = Thread(target=self.thread_consumer,
                             args=(self.stopevent,))
        self.busy = False
        self.thread.start()

    def stop(self) -> None:
        logger.debug("Stopping thread %s...", self.thread_id)
        self.stopevent.set()
        self.is_stopping = True
        if self.current_module_obj:
            self.current_module_obj.kill()
            

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
            self.current_module_obj = module_object
            module_object.start()
        finally:
            if self.is_stopping:
                if self.current_job:
                    try:
                        hostobj = TestHost(job["target"])
                        if job["job_id"] in hostobj.tests_state and hostobj.tests_state[job["job_id"]]["state"] != "done":
                            logger.debug("Setting test to stopped: %s", hostobj.tests_state[job["job_id"]])
                            hostobj.set_test_state(job["job_id"], "stopped")
                    except Exception as ie:
                        logger.error(
                        "Error in thread close: %s", ie)
            self.busy = False
            self.current_job = None
            self.current_job_date = None
            self.current_module_obj = None
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
                    
    def get_progress(self):
        if not self.current_module_obj :
            return ""
        else:
            return self.current_module_obj.progress
        
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
                    "Error happened in Worker Consumer Thread %s with data:\n%s\n: %s",
                    self.thread_id,
                    job.data,
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
    _callback = None
    queue = PriorityQueue(QUEUE_SIZE)
    watchdog = None
    

    def add_job(job: dict) -> None:
        if "priority" not in job:
            logger.warn("Job %s has no priority", job)
            job["priority"] = 1000
        if int(job["priority"]) < 0:
            logger.info("Skipping job %s because priority is %s (probably ignored because of list size)", job["job_id"], job["priority"])
            hostobj = TestHost(job["target"])
            hostobj.set_test_state(job["job_id"], "ignored", priority=job["priority"])
            return

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

    def start_threads(complete_callback, finish_callback = None):
        """Start the worker threads

        Args:
            complete_callback (func): Callback notification when a thread is done
        """
        if not complete_callback:
            complete_callback = WorkThreader.stop_if_finish()
        WorkThreader._callback = complete_callback
        WorkThreader._finishcallback = finish_callback
        for i in range(0, NUM_THREADS):
            logger.info("Creating Worker thread %s", i)
            WorkThreader._instances[str(i)] = _WorkThread(
                i, WorkThreader.queue, complete_callback
            )
        WorkThreader.watchdog = Watchdog()
        
    def stop_if_finish():
        if WorkThreader.finished():
            logger.info("stop_if_finish: jobs finished, quitting")
            WorkThreader.stop_threads()

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
        if WorkThreader._finishcallback:
            WorkThreader._finishcallback()
