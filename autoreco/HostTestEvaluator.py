from .logger import logger
from .TestHost import TestHost
from .State import State
from .config import WEB_WORDLISTS, GOBUSTER_FILE_EXT, USERENUM_LISTS, CREDENTIALS_FILE, RUN_SCANS
from .TestEvaluatorBase import TestEvaluatorBase

from pathlib import Path
import re
import os


class HostTestEvaluator(TestEvaluatorBase):
    """
    This class scans known hosts in state, and suggest additional tests to run
    It will always return all possible tests for this host, then the TestRunner will only run tests not run previously
    For this to work, it is important that a test with unique parameters generate always the same job id, and that this job ID is unique to this test / parameters combination
    """

    def __init__(self, hostobject: TestHost):
        self.hostobject = hostobject

    def get_tests(self):
        global RUN_SCANS
        logger.debug("Evaluating tests for host %s ...", self.hostobject)
        tests = {}
        # Always running generic tests for service discovery
        tests = self._safe_merge(tests, self.get_generic_tests())

        if "all" in RUN_SCANS or "nmapscan" in RUN_SCANS:
            try:
                tests = self._safe_merge(tests, self.get_nmap_specific_tests())
            except Exception as e:
                logger.error("Error when getting nmap tests: ",
                             e, exc_info=True)
        if "all" in RUN_SCANS or "dns" in RUN_SCANS:
            try:
                tests = self._safe_merge(tests, self.get_dns_tests())
            except Exception as e:
                logger.error("Error when getting dns tests: ",
                             e, exc_info=True)
        if "all" in RUN_SCANS or "file" in RUN_SCANS:
            try:
                tests = self._safe_merge(tests, self.get_file_tests())
            except Exception as e:
                logger.error("Error when getting file tests: ",
                             e, exc_info=True)
        if "all" in RUN_SCANS or "webdiscovery" in RUN_SCANS:
            try:
                tests = self._safe_merge(tests, self.get_scan_web_tests())
            except Exception as e:
                logger.error("Error when getting scan web tests: ",
                             e, exc_info=True)
        if "all" in RUN_SCANS or "webfiles" in RUN_SCANS:
            try:
                tests = self._safe_merge(tests, self.get_web_file_tests())
            except Exception as e:
                logger.error("Error when getting web file tests: ",
                             e, exc_info=True)
        if "all" in RUN_SCANS or "snmp" in RUN_SCANS:
            try:
                tests = self._safe_merge(tests, self.get_snmp_tests())
            except Exception as e:
                logger.error("Error when getting snmp tests: ",
                             e, exc_info=True)

        # logger.debug("Tests for host %s: \n %s", self.hostobject, tests)

        # AD / Users tests
        if "all" in RUN_SCANS or "userenum" in RUN_SCANS:
            try:
                tests = self._safe_merge(tests, self.get_ad_users_tests())
            except Exception as e:
                logger.error("Error when getting ad user tests: ",
                             e, exc_info=True)
        if "all" in RUN_SCANS or "exploits" in RUN_SCANS:
            try:
                tests = self._safe_merge(tests, self.searchsploit_test())
            except Exception as e:
                logger.error(
                    "Error when getting searchsploit tests: ", e, exc_info=True)

        return tests

    def nmap_scans_complete(self):
        state = State().TEST_STATE.copy()
        if "discovery" in state and "tests_state" in state["discovery"]:
            for testid, testdata in state["discovery"]["tests_state"].items():
                if "nmap" in testdata["module_name"].lower() and testdata["state"] in ["notstarted", "started", "queued"]:
                    logger.debug(
                        "nmap_scans_complete discovery not complete because test %s", self.hostobject.ip, testid)
                    return False
        else:
            if len(self.hostobject.tests_state.keys()) < 1:
                return False  # not started
        for testid, testdata in self.hostobject.tests_state.items():
            logger.debug("testid, testdata: %s / %s", testid, testdata)
            if "nmap" in testdata["module_name"].lower() and testdata["state"] in ["notstarted", "started", "queued"]:
                logger.debug(
                    "nmap_scans_complete for host %s not complete because test %s", self.hostobject.ip, testid)
                return False
        logger.debug("NMAP Tests complete on host %s", self.hostobject.ip)
        return True

    def get_known_credentials(self):
        global CREDENTIALS_FILE
        creds = []
        if not CREDENTIALS_FILE or not os.path.exists(CREDENTIALS_FILE):
            if os.path.exists(os.path.join(State().TEST_WORKING_DIR, "creds.txt")):
                CREDENTIALS_FILE = os.path.join(
                    State().TEST_WORKING_DIR, "creds.txt")
            else:
                return creds
        with open(CREDENTIALS_FILE, "r") as f:
            creds = [x.split(":") for x in f.readlines()]
        return creds

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

    def get_ad_dc_ips(self):
        dcs = []

        state = State().TEST_STATE.copy()
        for k, v in state.items():
            if k == "discovery":
                continue
            hostobj = TestHost(k)
            if hostobj.os_family and "windows" not in hostobj.os_family.lower():
                continue
            if "kerberos-sec" in hostobj.services and "ldap" in hostobj.services:  # TODO maybe needs improvement
                dcs.append(k)
        logger.debug("Known DCs: %s", dcs)
        return dcs

    def is_dc(self):
        return self.hostobject.ip in self.get_ad_dc_ips()

    def get_ad_users_tests(self):
        global USERENUM_LISTS
        tests = {}
        if not self.is_dc():
            return tests

        # Domain detected automatically
        jobid = f"userenum.NetExecRIDBrute_{self.hostobject.ip}_ridbrute_{file}_{d}"
        tests[jobid] = {
            "module_name": "userenum.NetExecRIDBrute",
            "job_id": jobid,
            "target": self.hostobject.ip,
            "priority": 500,
            "args": {},
        }

        doms = self.get_known_domains()

        for d in doms:
            for w in USERENUM_LISTS:
                file = Path(w).stem
                jobid = f"userenum.Kerbrute_{self.hostobject.ip}_kerbrute_users_{file}_{d}"
                tests[jobid] = {
                    "module_name": "userenum.Kerbrute",
                    "job_id": jobid,
                    "target": self.hostobject.ip,
                    "priority": self.get_list_priority(w),
                    "args": {"domain": "d", "wordlist": w},
                }
        # netexec credentialed enum
        for action in ["loggedon-users", "groups", "users"]:
            for p in ["smb", "winrm"]:
                for creds in self.get_known_credentials():
                    jobid = f"userenum.NetExecUserEnum_{self.hostobject.ip}_netexec_{p}_{action}_{creds[0]}"
                    tests[jobid] = {
                        "module_name": "userenum.NetExecUserEnum",
                        "job_id": jobid,
                        "target": self.hostobject.ip,
                        "priority": 100,
                        "args": {"action": action, "protocol": p, "user": creds[0], "password": creds[1]},
                    }

        return tests

    def searchsploit_test(self):
        tests = {}
        if not self.nmap_scans_complete():
            return tests
        jobid = f"hostscan.SearchSploit_{self.hostobject.ip}_searchsploit"
        tests[jobid] = {
            "module_name": "hostscan.SearchSploit",
            "job_id": jobid,
            "target": self.hostobject.ip,
            "priority": 50,
            "args": {},
        }
        return tests

    def get_file_tests(self):
        tests = {}
        if (
            "microsoft-ds" in self.hostobject.services
        ):
            jobid = f"hostscan.NetExecHostScan_{self.hostobject.ip}_netexec_smbshares_spider"
            tests[jobid] = {
                "module_name": "hostscan.NetExecHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "priority": 100,
                "args": {"action": "shares", "spider": True},
            }
            # Credentialed SMB Share Listing
            for creds in self.get_known_credentials():
                jobid = f"hostscan.NetExecHostScan_{self.hostobject.ip}_netexec_smbshares_spider_{creds[0]}"
                tests[jobid] = {
                    "module_name": "hostscan.NetExecHostScan",
                    "job_id": jobid,
                    "target": self.hostobject.ip,
                    "priority": 100,
                    "args": {"action": "shares", "spider": True, "user": creds[0], "password": creds[1]},
                }
        return tests

    def get_snmp_tests(self):
        """Create snmp jobs

        Returns:
            dict: jobs
        """
        global WEB_WORDLISTS
        tests = {}
        # TODO SNMP / onesixtyone
        # Should assume snmptrap/162 does SNMP ?
        return tests

    def get_dns_tests(self):
        """Create dns jobs

        Returns:
            dict: jobs
        """
        global WEB_WORDLISTS
        tests = {}
        doms = self.get_known_domains()
        for s in ["domain"]:
            if (
                s in self.hostobject.udp_service_ports
            ):  # Dont think DNS would run on sth else than 53 but who knows
                for p in self.hostobject.udp_service_ports[s]:
                    for d in doms:
                        for w in WEB_WORDLISTS["dns"]:
                            file = Path(w).stem
                            jobid = f"hostscan.GoBuster_dns_{self.hostobject.ip}_{s}_{p}_{file}_{d}"
                            tests[jobid] = {
                                "module_name": "hostscan.GoBuster",
                                "job_id": jobid,
                                "target": self.hostobject.ip,
                                "priority": self.get_list_priority(w),
                                "args": {
                                    "mode": "dns",
                                    "domain": d,
                                    "wordlist": w,
                                },
                            }
        return tests

    def get_nmap_specific_tests(self):
        tests = {}
        if (
            "microsoft-ds" in self.hostobject.services
        ):
            ports = self.get_tcp_services_ports(["microsoft-ds"])
            jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_smbenum_{ports}"
            tests[jobid] = {
                "module_name": "hostscan.NmapHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "priority": 100,
                "args": {"script": "smb-enum*", "ports": ports},
            }
            jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_smbvuln_{ports}"
            tests[jobid] = {
                "module_name": "hostscan.NmapHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "priority": 100,
                "args": {"script": "smb-vuln*", "ports": ports},
            }

        if "http" in self.hostobject.services or "https" in self.hostobject.services:
            ports = self.get_tcp_services_ports(["http", "https"])
            jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_httpscript_{ports}"
            tests[jobid] = {
                "module_name": "hostscan.NmapHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "priority": 100,
                "args": {"script": "default,auth,brute,discovery,vuln", "ports": ports},
            }

        if "ldap" in self.hostobject.services:
            ports = self.get_tcp_services_ports(["ldap"])
            jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_ldapscript_{ports}"
            tests[jobid] = {
                "module_name": "hostscan.NmapHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "priority": 100,
                "args": {"script": "'ldap* and not brute'", "ports": ports},
            }

        if ("nfs" in self.hostobject.services or
            "rpcbind" in self.hostobject.services
            ):
            ports = self.get_tcp_services_ports(["nfs", "rpcbind"])
            if len(ports) > 0:
                jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_nfsscript_{ports}"
                tests[jobid] = {
                    "module_name": "hostscan.NmapHostScan",
                    "job_id": jobid,
                    "target": self.hostobject.ip,
                    "priority": 100,
                    "args": {"script": "nfs-*", "ports": ports},
                }
            ports = self.get_udp_services_ports(["nfs", "rpcbind"])
            if len(ports) > 0:
                jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_nfsscript_udp_{ports}"
                tests[jobid] = {
                    "module_name": "hostscan.NmapHostScan",
                    "job_id": jobid,
                    "target": self.hostobject.ip,
                    "priority": 100,
                    "args": {"script": "nfs-*", "ports": ports, "protocol": "udp"},
                }
        return tests

    def get_known_domains(self):

        doms = State().KNOWN_DOMAINS.copy()
        state = State().TEST_STATE.copy()
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
        State().KNOWN_DOMAINS = doms  # .copy() # Statewrapper always copy
        logger.debug("Known Domains: %s", doms)
        return doms

    def get_web_file_tests(self):
        """Create GoBuster file jobs

        Returns:
            dict: jobs
        """
        global WEB_WORDLISTS, GOBUSTER_FILE_EXT
        tests = {}
        for s in ["http", "https"]:
            # Running tests against IP
            if s in self.hostobject.tcp_service_ports:
                for p in self.hostobject.tcp_service_ports[s]:
                    for w in WEB_WORDLISTS["files"]:
                        file = Path(w).stem
                        jobid = f"hostscan.GoBuster_dirf_{self.hostobject.ip}_{s}_{p}_{file}"
                        tests[jobid] = {
                            "module_name": "hostscan.GoBuster",
                            "job_id": jobid,
                            "target": self.hostobject.ip,
                            "priority": self.get_list_priority(w),
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
                                "priority": self.get_list_priority(w),
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

    def get_scan_web_tests(self):
        """Create GoBuster jobs

        Returns:
            dict: jobs
        """
        global WEB_WORDLISTS
        tests = {}
        doms = self.get_known_domains()
        for s in ["http", "https"]:
            # Running tests against IP
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
                            "priority": self.get_list_priority(w),
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
                                "priority": self.get_list_priority(w),
                                "args": {
                                    "url": f"{s}://{self.hostobject.ip}:{p}",
                                    "mode": "dir",
                                    "host": h,
                                    "wordlist": w,
                                },
                            }
                    # Trying to get new VHosts
                    for w in WEB_WORDLISTS["vhost"]:
                        for d in doms:
                            file = Path(w).stem
                            jobid = f"hostscan.FFUF_vh_{self.hostobject.ip}_{s}_{p}_{file}_{d}"
                            tests[jobid] = {
                                "module_name": "hostscan.FFUF",
                                "job_id": jobid,
                                "target": self.hostobject.ip,
                                "priority": self.get_list_priority(w),
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
        jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_quick_tcp"
        tests[jobid] = {
            "module_name": "hostscan.NmapHostScan",
            "job_id": jobid,
            "target": self.hostobject.ip,
            "priority": 100,
            "args": {"protocol": "tcp", "ports": "--top-ports 150"},
        }

        for proto in ["tcp", "udp"]:
            jobid = f"hostscan.NmapHostScan_{self.hostobject.ip}_{proto}"
            tests[jobid] = {
                "module_name": "hostscan.NmapHostScan",
                "job_id": jobid,
                "target": self.hostobject.ip,
                "priority": 200,
                "args": {"protocol": proto, "script": "default,vuln"},
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
