from .logger import logger

from .utils import get_state_dns_servers
from .config import CREDENTIALS_FILE, RUN_SCANS, NETEXEC_DISCOVERY_PROTOCOLS, NETEXEC_USERENUM_PROTOCOLS
from .TestEvaluatorBase import TestEvaluatorBase

from pathlib import Path



class DiscoveryTestEvaluator(TestEvaluatorBase):
    """
    This class scans known hosts in state, and suggest additional tests to run
    It will always return all possible tests for this host, then the TestRunner will only run tests not run previously
    For this to work, it is important that a test with unique parameters generate always the same job id, and that this job ID is unique to this test / parameters combination
    """

    def __init__(self, subnet ):
        self.subnet = subnet
        if self.subnet:
            self.subnet_str = self.subnet.replace("/", "_")
        else:
            self.subnet_str = "nosubnet"


        
    def get_tests(self):
        """Get all host tests, according to RUN_SCANS 

        Returns:
            dict: jobs
        """
        global RUN_SCANS
        logger.debug("Evaluating Discovery tests for subnet %s ...", self.subnet)
        tests = {}
        # Always running generic tests for service discovery
        tests = self._safe_merge(tests, self.get_nmap_discovery())

        if "all" in RUN_SCANS or "file" in RUN_SCANS:
            try:
                pass
                tests = self._safe_merge(tests, self.get_file_tests())
            except Exception as e:
                logger.error("Error when getting Discovery file tests: %s",
                             e, exc_info=True)
        # AD / Users tests
        if "all" in RUN_SCANS or "userenum" in RUN_SCANS:
            try:

                tests = self._safe_merge(tests, self.get_credtest_tests())
                tests = self._safe_merge(tests, self.get_user_tests())
            except Exception as e:
                logger.error("Error when getting ad user tests: %s",
                             e, exc_info=True)
      
        return tests



    def get_nmap_discovery(self):    
        tests = {}
        if not self.subnet:
            logger.debug("No subnet, skipping nmap discovery")
            return tests
        
        global NETEXEC_DISCOVERY_PROTOCOLS
        jobid = f"discovery.NmapSubnetPing_{self.subnet_str}"
        job = {
            "module_name": "discovery.NmapSubnetPing",
            "job_id": jobid,
            "target": self.subnet,
            "priority": 10,
            "args": {},
        }
        tests[jobid] = job

        
        for proto in NETEXEC_DISCOVERY_PROTOCOLS:
            jobid = f"discovery.NetExecDiscovery_{self.subnet_str}_{proto}"
            job = {
                "module_name": "discovery.NetExecDiscovery",
                "job_id": jobid,
                "target": self.subnet,
                "priority": 10,
                "args": {"protocol": proto},
            }
            tests[jobid] = job
        return tests
    

    
    def get_credtest_tests(self):
        # Testing credentials against known services        
        tests = {}
        target = self.subnet
        targetstr = self.subnet_str
        if not target:
            target = " ".join(self.get_known_hosts()) 
            targetstr = "hosts" + str(len(self.get_known_hosts()))
        for p in NETEXEC_USERENUM_PROTOCOLS: # TODO: Support secure ldap ?
            if p == "ldap" and len(get_state_dns_servers())<1:
                logger.info("Skipping LDAP NetExecUserEnum tests for now because no DNS server found")
                continue
            for creds in self.get_known_credentials():
                    jobid = f"userenum.NetExecUserEnum_{targetstr}_netexec_credtest_{p}_{self._get_creds_job_id(creds)}"
                    tests[jobid] = {
                        "module_name": "userenum.NetExecUserEnum",
                        "job_id": jobid,
                        "target": target,
                        "priority": 100,
                        "args": { "protocol": p, "user": creds[0], "password": creds[1], "credtest": "credtest"},
                    }
        return tests



  
    def get_user_tests(self):
        tests = {}
        target = self.subnet
        targetstr = self.subnet_str
        if not target:
            target = " ".join(self.get_known_hosts()) #TODO Test
            targetstr = "hosts" + str(len(self.get_known_hosts()))
        for action in ["loggedon-users"]:
            for p in ["smb"]: # Seems only SMB works for this
                for creds in self.get_known_credentials():
                    jobid = f"userenum.NetExecUserEnum_{targetstr}_netexec_{p}_{action}_{self._get_creds_job_id(creds)}"
                    tests[jobid] = {
                        "module_name": "userenum.NetExecUserEnum",
                        "job_id": jobid,
                        "target": target,
                        "priority": 200,
                        "args": {"action": action, "protocol": p, "user": creds[0], "password": creds[1]},
                    }
        return tests
    
    def get_file_tests(self):
        tests = {}
        target = self.subnet
        targetstr = self.subnet_str
        if not target:
            target = " ".join(self.get_known_hosts()) #TODO Test
            targetstr = "hosts" + str(len(self.get_known_hosts()))
        for action in ["shares"]:
            for p in ["smb"]: #  only SMB works for this
                for creds in self.get_known_credentials():
                    jobid = f"discovery.NetExecDiscovery_{targetstr}_{p}_{action}_{self._get_creds_job_id(creds)}"
                    job = {
                        "module_name": "discovery.NetExecDiscovery",
                        "job_id": jobid,
                        "target": self.subnet,
                        "priority": 50,
                        "args": {"protocol": p, "user": creds[0], "password": creds[1], "action": action},
                    }
                    tests[jobid] = job
        return tests
    
