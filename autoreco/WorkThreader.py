
from threading import Thread
from threading import Event
from queue import Queue, Empty
from .logger import logger
from .config import NUM_THREADS, QUEUE_SIZE, QUEUE_WAIT_TIME
from .modules.ModuleLoader import ModuleLoader
"""
Job Syntax:
"""
JOB_TEMPLATE = {
    "module_name": "",
    "job_id":"",
    "target":"",
    "args": {}
}
class _WorkThread():
    def __init__(self, thread_id: str, queue: Queue,  complete_callback):
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
            #def __init__(self, testid, host, args = {}):
            module_object = self.modules[job["module_name"]](job["job_id"], job["target"], job["args"])
            module_object.start()
        finally:
            if self.complete_callback:
                try:
                    self.complete_callback()
                except Exception as e:
                    logger.error("Error in thread %s: %s", self.id, e, exc_info=True)



    def thread_consumer(self, stopevent):
        """The Queue Consumer thread callback function
        """
        logger.debug('Consumer Thread %s: Running', self.thread_id)
        # consume items
        while not stopevent.is_set():
            jobget = False
            try:            
                job = self.queue.get(timeout=QUEUE_WAIT_TIME)
                jobget = True
                logger.debug('processing job %s ...', job)
                self.process_job(job)
                logger.debug('processing job %s ... Done', job)
            except Empty:
                # This will happen if queue is empty. 
                # We use this so that threads are not waiting infinitely on the queue
                # And can get the stop event set.
                pass 

            except Exception as e:
                logger.error(
                    "Error happened in Worker Consumer Thread %s: %s", self.thread_id, e, exc_info=True)
            finally:
                if jobget:
                    logger.debug("Task done %s", self.thread_id)
                    self.queue.task_done()
        logger.debug("Stopping thread %s... Done", self.thread_id)


class WorkThreader():
    _instances = {}
    queue = Queue(QUEUE_SIZE)

    # TODO Implement Watchdog or something
    def add_job(job: dict):
        WorkThreader.queue.put(job)

    def start_threads(complete_callback):
        for i in range (0, NUM_THREADS):
            logger.info("Creating Terraform Worker thread for instance %s", i)
            WorkThreader._instances[str(i)] = _WorkThread(i, WorkThreader.queue, complete_callback)
    
    def stop_threads():
        for i in range (0, NUM_THREADS):
            WorkThreader._instances[str(i)].stop()
            del WorkThreader._instances[str(i)]
