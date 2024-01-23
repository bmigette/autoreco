
from .logger import logger

class HostTestEvaluator():
    def __init__(self, hostobject):
        self.hostobject = hostobject
        
    def _safe_merge(self, d1, d2):
        tempd = d1.copy()
        for k,v in d2.items():
            if k in tempd:
                raise Exception(f"{k} is already in dict")
            tempd[k] = v
        return tempd
    
    def get_tests(self):
        logger.debug("Evaluating tests for host %s ...", self.hostobject)
        tests = {}
        tests = self._safe_merge(tests, self.get_generic_tests())
        
        logger.debug("Tests for host %s: \n %s", self.hostobject, tests)
        return tests

    
    def get_generic_tests(self):
        tests = {}
        for proto in ["tcp", "udp"]:
            jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_{proto}"
            tests[jobid] = {
                    "module_name": "hostscan.NmapHostScan",
                    "job_id": jobid,
                    "target": self.hostobject.ip,
                    "args": {"protocol": proto}    
            }
        return tests
        