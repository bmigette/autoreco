from threading import Thread
from threading import Event
from queue import Queue, Empty
from .logger import logger
from .config import NUM_THREADS, QUEUE_SIZE, QUEUE_WAIT_TIME
from .modules.ModuleLoader import ModuleLoader
from datetime import datetime

"""
Job Syntax:
"""
JOB_TEMPLATE = {"module_name": "", "job_id": "", "target": "", "args": {}}


class _WorkThread:
    """Single thread class. This class is the one picking up jobs from the queue, and executing it with appropriate module"""

    def __init__(self, thread_id: str, queue: Queue, complete_callback):
        """Constructor

        Args:
            thread_id (str): Thread ID
            queue (Queue): Jobs queue object
            complete_callback (function): Callback to run when a job is complete to trigger changes
        """
        self.thread_id = thread_id
        self.queue = queue
        self.complete_callback = complete_callback
        self.modules = ModuleLoader.get_modules()
        self.stopevent = Event()
        self.thread = Thread(target=self.thread_consumer, args=(self.stopevent,))
        self.busy = False
        self.thread.start()

    def stop(self):
        logger.debug("Stopping thread %s...", self.thread_id)
        self.stopevent.set()

    def process_job(self, job: dict):
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
            self.busy = True
            module_object = self.modules[job["module_name"]](
                job["job_id"], job["target"], job["module_name"], job["args"]
            )
            module_object.start()
        finally:
            self.busy = False
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
                job = self.queue.get(timeout=QUEUE_WAIT_TIME)
                jobget = True
                logger.debug("processing job %s ...", job)
                self.process_job(job)
                logger.debug("processing job %s ... Done", job)
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
    queue = Queue(QUEUE_SIZE)

    def add_job(job: dict):
        logger.debug("Adding job with data %s", job)
        WorkThreader.queue.put(job)
        logger.debug("======== QUEUE SIZE: %s ========", WorkThreader.queue.qsize())

    def start_threads(complete_callback):  # TODO: Create a watchdog that prints state
        for i in range(0, NUM_THREADS):
            logger.info("Creating Worker thread %s", i)
            WorkThreader._instances[str(i)] = _WorkThread(
                i, WorkThreader.queue, complete_callback
            )

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

    def stop_threads():
        logger.info("Stopping threads...")
        for i, inst in WorkThreader._instances.items():
            inst.stop()

        for i, inst in WorkThreader._instances.items():
            inst.thread.join()
            del inst
