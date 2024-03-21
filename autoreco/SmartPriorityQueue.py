
from queue import Queue

from .logger import logger
from .config import MAX_JOB_PER_HOST, MAX_JOB_PER_HOST_PORT
from .TestJob import TestJob

class SmartPriorityQueue(Queue):
    '''Smart Priority Queue
    '''

    def _init(self, maxsize):
        self.queue = []
        self.threads = None

    def _qsize(self):
        return len(self.queue)

    def _put(self, item):
        self.queue.append(item)
         
    def sleep_job(self):
        data = {
            "module_name": "SleepModule",
            "job_id": "sleepjob",
            "target": "self",
            "args": {
                "sleep": 60
            }
        }
        return TestJob(1, data)
    
    def _job_eligible(self, hdata, job):
        if job.target not in hdata:
            return True
        
        if "/" in job.target:
            return True # We don't limit subnet discovery jobs
        service_ok = False
        if job.target_port: 
            if job.target_port in hdata[job.target]["services"]:                
                if hdata[job.target]["services"][job.target_port] >= MAX_JOB_PER_HOST_PORT:
                    logger.debug("Skipping host %s for job %s because MAX_JOB_PER_HOST_PORT on port %s", job.target, job.id, job.target_port)
                    return False
            else:
                service_ok = True
        if hdata[job.target]["jobcount"] < MAX_JOB_PER_HOST:
            return True
        
        logger.debug("Skipping host %s for job %s because MAX_JOB_PER_HOST", job.target, job.id)
        return False
        
    def _get_best_item(self):
        hdata = {}
        best_index = 0
        #best_index2 = 0
        best_prio = None
        #best_prio2 = None
        for k, t in self.threads.items():
            if not t.current_job_obj:
                continue
            if t.current_job_obj.target not in hdata:
                hdata[t.current_job_obj.target ] = {"jobcount": 0, "services": {}}
            hdata[t.current_job_obj.target]["jobcount"] += 1
            if  t.current_job_obj.target_port:
                if t.current_job_obj.target_port in hdata[t.current_job_obj.target]["services"]:
                    hdata[t.current_job_obj.target]["services"][t.current_job_obj.target_port] += 1
                else:
                    hdata[t.current_job_obj.target]["services"][t.current_job_obj.target_port] = 1
        logger.debug("thread jobs states: %s", hdata)
        for idx, qitem in enumerate(self.queue):
            # if not best_prio2:
            #     best_prio2 = qitem.priority
                
            # if qitem.priority < best_prio2:
            #     best_prio2 = qitem.priority
            #     best_index2 = idx
                
            if not self._job_eligible(hdata, qitem):
                continue
            
            if not best_prio:
                best_prio = qitem.priority
                best_index = idx
                logger.debug("setting best prio1 / index to %s / %s", best_prio,  best_index)
            if qitem.priority < best_prio:
                best_prio = qitem.priority
                best_index = idx
                logger.debug("setting best prio2 / index to %s / %s", best_prio,  best_index)
        if best_prio:
            r = self.queue.pop(best_index)
            logger.debug("Best Q Job: %s", r)
        else:
            logger.debug("Returning Sleep Job")
            r = self.sleep_job()

        return r
    
    def _get(self):
        return self._get_best_item()