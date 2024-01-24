from .logger import logger
from .TestHost import TestHost
from .state import domainlock, KNOWN_DOMAINS
from .config import GOBUSTER_WORDLISTS, GOBUSTER_FILE_EXT
from pathlib import Path


class HostTestEvaluator:
    """
    This class scans known hosts in state, and suggest additional tests to run
    It will always return all possible tests for this host, then the TestRunner will only run tests not run previously
    """

    def __init__(self, hostobject: TestHost):
        self.hostobject = hostobject

    def _safe_merge(self, d1, d2):
        tempd = d1.copy()
        for k, v in d2.items():
            if k in tempd:
                raise Exception(f"{k} is already in dict")
            tempd[k] = v
        return tempd

    def get_tests(self):
        logger.debug("Evaluating tests for host %s ...", self.hostobject)
        tests = {}
        tests = self._safe_merge(tests, self.get_generic_tests())
        tests = self._safe_merge(tests, self.get_nmap_specific_tests())
        tests = self._safe_merge(tests, self.get_dns_tests())
        tests = self._safe_merge(tests, self.get_web_tests())
        tests = self._safe_merge(tests, self.get_web_file_tests())

        logger.debug("Tests for host %s: \n %s", self.hostobject, tests)

        return tests

    def get_tcp_services_ports(self, services: list):
        r = []
        for s in services:
            if s in self.hostobject.tcp_service_ports:
                r.extend(self.hostobject.tcp_service_ports[s])
        return list(set(r))

    def get_udp_services_ports(self, services: list):
        r = []
        for s in services:
            if s in self.hostobject.udp_service_ports:
                r.extend(self.hostobject.udp_service_ports[s])
        return list(set(r))

    def get_dns_tests(self):
        """Create dns jobs

        Returns:
            dict: jobs
        """
        tests = {}
        for s in ["domain"]:
            if (
                s in self.hostobject.udp_service_ports
            ):  # Dont think DNS would run on sth else than 5353 but who knows
                for p in self.hostobject.udp_service_ports[s]:
                    for d in self.get_known_domains():
                        for w in GOBUSTER_WORDLISTS["dns"]:
                            file = Path(w).stem
                            jobid = f"hostscan.GoBuster_dns_{self.hostobject.ip}_{s}_{p}_{file}_{d}"
                            tests[jobid] = {
                                "module_name": "hostscan.GoBuster",
                                "job_id": jobid,
                                "target": self.hostobject.ip,
                                "args": {
                                    "mode": "dns",
                                    "domain": d,
                                },
                            }
        return tests

    def get_nmap_specific_tests(self):
        tests = {}
        if (
            "microsoft-ds" in self.hostobject.services
            or "netbios-ssn" in self.hostobject.services
        ):
            ports = self.get_tcp_services_ports(["microsoft-ds", "netbios-ssn"])
            jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_smbenum_{ports}"
            tests[jobid] = {
                "module_name": "hostscan.NmapHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "args": {"script": "smb-enum*", "ports": ports},
            }
            jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_smbvuln_{ports}"
            tests[jobid] = {
                "module_name": "hostscan.NmapHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "args": {"script": "smb-vuln*", "ports": ports},
            }
            
        if (
            "http" in self.hostobject.services
            or "https" in self.hostobject.services
        ):   
            ports = self.get_tcp_services_ports(["http", "https"])
            jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_httpscript_{ports}"
            tests[jobid] = {
                "module_name": "hostscan.NmapHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "args": {"script": "default,auth,brute,discovery,vuln", "ports": ports},
            }
        
        return tests

    def get_known_domains(self):
        # TODO: Parse domain names from state
        with domainlock:
            doms = KNOWN_DOMAINS.copy()
        return doms

    def get_web_file_tests(self):
        """Create GoBuster file jobs

        Returns:
            dict: jobs
        """
        tests = {}
        for s in ["http", "https"]:
            ### Running tests against IP
            if s in self.hostobject.tcp_service_ports:
                for p in self.hostobject.tcp_service_ports[s]:
                    for w in GOBUSTER_WORDLISTS["files"]:
                        file = Path(w).stem
                        jobid = f"hostscan.GoBuster_dirf_{self.hostobject.ip}_{s}_{p}_{file}"
                        tests[jobid] = {
                            "module_name": "hostscan.GoBuster",
                            "job_id": jobid,
                            "target": self.hostobject.ip,
                            "args": {
                                "url": f"{s}://{self.hostobject.ip}:{p}",
                                "extensions": GOBUSTER_FILE_EXT,
                                "mode": "dir",
                                "wordlist": w,
                                "fsrc": "fsrc" # This is only to display in log filename
                            },
                        }

                        for h in self.hostobject.hostnames:
                            jobid = f"hostscan.GoBuster_dirf_{h}_{s}_{p}_{file}"
                            tests[jobid] = {
                                "module_name": "hostscan.GoBuster",
                                "job_id": jobid,
                                "target": self.hostobject.ip,
                                "args": {
                                    "url": f"{s}://{h}:{p}",
                                    "extensions": GOBUSTER_FILE_EXT,
                                    "wordlist": w,
                                    "mode": "dir",
                                    "fsrc": "fsrc" # This is only to display in log filename
                                },
                            }

        return tests

    def get_web_tests(self):
        """Create GoBuster jobs

        Returns:
            dict: jobs
        """
        tests = {}
        for s in ["http", "https"]:
            ### Running tests against IP
            if s in self.hostobject.tcp_service_ports:
                for p in self.hostobject.tcp_service_ports[s]:
                    for w in GOBUSTER_WORDLISTS["dir"]:
                        file = Path(w).stem
                        jobid = (
                            f"hostscan.GoBuster_dir_{self.hostobject.ip}_{s}_{p}_{file}"
                        )
                        tests[jobid] = {
                            "module_name": "hostscan.GoBuster",
                            "job_id": jobid,
                            "target": self.hostobject.ip,
                            "args": {
                                "url": f"{s}://{self.hostobject.ip}:{p}",
                                "wordlist": w,
                                "mode": "dir",
                            },
                        }

                        for h in self.hostobject.hostnames:
                            jobid = f"hostscan.GoBuster_dir_{h}_{s}_{p}_{file}"
                            tests[jobid] = {
                                "module_name": "hostscan.GoBuster",
                                "job_id": jobid,
                                "target": self.hostobject.ip,
                                "args": {
                                    "url": f"{s}://{h}:{p}",
                                    "wordlist": w,
                                    "mode": "dir",
                                },
                            }
                    ## Trying to get new VHosts
                    for w in GOBUSTER_WORDLISTS["vhost"]:
                        for d in self.get_known_domains():
                            file = Path(w).stem
                            jobid = f"hostscan.GoBuster_vh_{self.hostobject.ip}_{s}_{p}_{file}_{d}"
                            tests[jobid] = {
                                "module_name": "hostscan.GoBuster",
                                "job_id": jobid,
                                "target": self.hostobject.ip,
                                "args": {
                                    "url": f"{s}://{self.hostobject.ip}:{p}",
                                    "mode": "dir",
                                    "domain": d,
                                    "wordlist": w,
                                },
                            }
        return tests

    def get_generic_tests(self):
        tests = {}
        for proto in ["tcp", "udp"]:
            jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_{proto}"
            tests[jobid] = {
                "module_name": "hostscan.NmapHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "args": {"protocol": proto},
            }

        if (
            "microsoft-ds" in self.hostobject.services
            or "netbios-ssn" in self.hostobject.services
        ):
            jobid = f"hostscan.Enum4Linux_{self.hostobject.ip}"
            tests[jobid] = {
                "module_name": "hostscan.Enum4Linux",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "args": {},
            }
        return tests
