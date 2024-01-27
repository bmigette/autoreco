from .logger import logger
from .TestHost import TestHost
from .state import domainlock, KNOWN_DOMAINS, statelock, TEST_STATE
from .config import WEB_WORDLISTS, GOBUSTER_FILE_EXT, WORD_LIST_LARGE_THRESHOLD
from pathlib import Path
import re


class HostTestEvaluator:
    """
    This class scans known hosts in state, and suggest additional tests to run
    It will always return all possible tests for this host, then the TestRunner will only run tests not run previously
    For this to work, it is important that a test with unique parameters generate always the same job id, and that this job ID is unique to this test / parameters combination
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
        tests = self._safe_merge(tests, self.get_file_tests())
        tests = self._safe_merge(tests, self.get_web_tests())
        tests = self._safe_merge(tests, self.get_web_file_tests())
        # TODO NFS Scan
        # TODO SNMP / onesixtyone
        # logger.debug("Tests for host %s: \n %s", self.hostobject, tests)

        return tests

    def is_large_list(self, wordlistfile):
        with open(wordlistfile, 'r') as fp:
            cnt = len(fp.readlines())
        return cnt >= WORD_LIST_LARGE_THRESHOLD

    def get_ad_dc_ips(self):
        dcs = []
        with statelock:
            state = TEST_STATE.copy()
        for k, v in state.items():
            if k == "discovery":
                continue
            hostobj = TestHost(k)
            if hostobj.os_family and "windows" not in hostobj.os_family.lower():
                continue
            if "kerberos-sec" in hostobj.services and "ldap" in hostobj.services: # TODO maybe needs improve
                dcs.append(k)
        logger.debug("Known DCs: %s", dcs)
        return dcs

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

    def get_file_tests(self):
        tests = {}
        if (
            "microsoft-ds" in self.hostobject.services
            or "netbios-ssn" in self.hostobject.services
        ):
            jobid = f"hostscan.NetExecHostScan_{self.hostobject.ip}_netexec_smbshares_spider"
            tests[jobid] = {
                "module_name": "hostscan.NetExecHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "priority": 100,
                "args": {"action": "shares", "spider": True},
            }
        return tests

    def get_dns_tests(self):
        """Create dns jobs

        Returns:
            dict: jobs
        """
        tests = {}
        doms = self.get_known_domains()
        for s in ["domain"]:
            if (
                s in self.hostobject.udp_service_ports
            ):  # Dont think DNS would run on sth else than 5353 but who knows
                for p in self.hostobject.udp_service_ports[s]:
                    for d in doms:
                        for w in WEB_WORDLISTS["dns"]:
                            file = Path(w).stem
                            jobid = f"hostscan.GoBuster_dns_{self.hostobject.ip}_{s}_{p}_{file}_{d}"
                            tests[jobid] = {
                                "module_name": "hostscan.GoBuster",
                                "job_id": jobid,
                                "target": self.hostobject.ip,
                                "priority": 1000 if self.is_large_list(w) else 100,
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
                "priority": 10,
                "args": {"script": "smb-enum*", "ports": ports},
            }
            jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_smbvuln_{ports}"
            tests[jobid] = {
                "module_name": "hostscan.NmapHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "priority": 10,
                "args": {"script": "smb-vuln*", "ports": ports},
            }

        if "http" in self.hostobject.services or "https" in self.hostobject.services:
            ports = self.get_tcp_services_ports(["http", "https"])
            jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_httpscript_{ports}"
            tests[jobid] = {
                "module_name": "hostscan.NmapHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "priority": 10,
                "args": {"script": "default,auth,brute,discovery,vuln", "ports": ports},
            }
        if "ldap" in self.hostobject.services:
            ports = self.get_tcp_services_ports(["ldap"])
            jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_ldapscript_{ports}"
            tests[jobid] = {
                "module_name": "hostscan.NmapHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "priority": 10,
                "args": {"script": "'ldap* and not brute'", "ports": ports},
            }

        return tests

    def get_known_domains(self):
        global KNOWN_DOMAINS, TEST_STATE
        with domainlock:
            doms = KNOWN_DOMAINS.copy()
        with statelock:
            state = TEST_STATE.copy()
        for k, v in state.items():
            if k == "discovery":
                continue
            hostobj = TestHost(k)
            if hostobj.domain:
                doms.append(hostobj.domain)
            for hostname in hostobj.hostnames:
                parts = hostname.split(".")
                if len(parts) > 1:
                    doms.append(".".join(parts[-2:]))
        doms2 = []
        for d in doms:
            d = d.lower()
            d = re.sub(r"[^a-zA-Z0-9\.\-]+", "", d)
            if d:
                doms2.append(d)
        doms = list(set(doms2))
        with domainlock:
            KNOWN_DOMAINS = doms.copy()
        logger.debug("Known Domains: %s", doms)
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
                    for w in WEB_WORDLISTS["files"]:
                        file = Path(w).stem
                        jobid = f"hostscan.GoBuster_dirf_{self.hostobject.ip}_{s}_{p}_{file}"
                        tests[jobid] = {
                            "module_name": "hostscan.GoBuster",
                            "job_id": jobid,
                            "target": self.hostobject.ip,
                            "priority": 1000 if self.is_large_list(w) else 100,
                            "args": {
                                "url": f"{s}://{self.hostobject.ip}:{p}",
                                "mode": "dir",
                                "extensions": GOBUSTER_FILE_EXT,
                                "wordlist": w,
                                "fsrc": "fsrc",  # This is only to display in log filename
                            },
                        }

                        for h in self.hostobject.hostnames:
                            if "." not in h:
                                if self.hostobject.domain:
                                    h = f"{h}.{self.hostobject.domain}"
                                else:
                                    continue
                            jobid = f"hostscan.GoBuster_dirf_{h}_{s}_{p}_{file}"
                            tests[jobid] = {
                                "module_name": "hostscan.GoBuster",
                                "job_id": jobid,
                                "target": self.hostobject.ip,
                                "priority": 1000 if self.is_large_list(w) else 100,
                                "args": {
                                    "url": f"{s}://{self.hostobject.ip}:{p}",
                                    "mode": "dir",
                                    "host": h,
                                    "extensions": GOBUSTER_FILE_EXT,
                                    "wordlist": w,
                                    "fsrc": "fsrc",  # This is only to display in log filename
                                },
                            }

        return tests

    def get_web_tests(self):
        """Create GoBuster jobs

        Returns:
            dict: jobs
        """
        tests = {}
        doms = self.get_known_domains()
        for s in ["http", "https"]:
            ### Running tests against IP
            if s in self.hostobject.tcp_service_ports:
                for p in self.hostobject.tcp_service_ports[s]:
                    for w in WEB_WORDLISTS["dir"]:
                        file = Path(w).stem
                        jobid = (
                            f"hostscan.GoBuster_dir_{self.hostobject.ip}_{s}_{p}_{file}"
                        )
                        tests[jobid] = {
                            "module_name": "hostscan.GoBuster",
                            "job_id": jobid,
                            "target": self.hostobject.ip,
                            "priority": 1000 if self.is_large_list(w) else 100,
                            "args": {
                                "url": f"{s}://{self.hostobject.ip}:{p}",
                                "mode": "dir",
                                "wordlist": w,
                            },
                        }

                        for h in self.hostobject.hostnames: 
                            if "." not in h:
                                if self.hostobject.domain:
                                    h = f"{h}.{self.hostobject.domain}"
                                else:
                                    continue
                            jobid = f"hostscan.GoBuster_dir_{h}_{s}_{p}_{file}"
                            tests[jobid] = {
                                "module_name": "hostscan.GoBuster",
                                "job_id": jobid,
                                "target": self.hostobject.ip,
                                "priority": 1000 if self.is_large_list(w) else 100,
                                "args": {
                                    "url": f"{s}://{self.hostobject.ip}:{p}",
                                    "mode": "dir",
                                    "host": h,
                                    "wordlist": w,
                                },
                            }
                    ## Trying to get new VHosts
                    for w in WEB_WORDLISTS["vhost"]:
                        for d in doms:
                            file = Path(w).stem
                            jobid = f"hostscan.FFUF_vh_{self.hostobject.ip}_{s}_{p}_{file}_{d}"
                            tests[jobid] = {
                                "module_name": "hostscan.FFUF",
                                "job_id": jobid,
                                "target": self.hostobject.ip,
                                "priority": 1000 if self.is_large_list(w) else 100,
                                "args": {
                                    "url": f"{s}://{self.hostobject.ip}:{p}",
                                    "mode": "vhost",
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
                "priority": 10,
                "args": {"protocol": proto},
            }

        if (
            "microsoft-ds" in self.hostobject.services
            or "netbios-ssn" in self.hostobject.services
            or "rpc" in self.hostobject.services
            or "msrpc" in self.hostobject.services
        ):
            jobid = f"hostscan.Enum4Linux_{self.hostobject.ip}"
            tests[jobid] = {
                "module_name": "hostscan.Enum4Linux",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "priority": 10,
                "args": {},
            }
        return tests
