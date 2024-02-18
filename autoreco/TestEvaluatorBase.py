from abc import abstractmethod, ABC
from .config import MAX_LIST_SIZE, WEB_WORDLISTS_FILES_HASEXT, CREDENTIALS_FILE
from .State import State
from .logger import logger
import re
import os
import hashlib
from .TestHost import TestHost



class TestEvaluatorBase(ABC):

    @abstractmethod
    def get_tests(self):
        #to override
        pass
    
    
    def _get_creds_job_id(self, creds):
        """Makes unique user/pass id for job ID

        Args:
            creds (tuple): user, pass

        Returns:
            str: job id user part
        """
        r = creds[0]
        if creds[1]:
            hash = hashlib.md5(creds[1].encode('utf-8')).hexdigest()
            r += "_" + hash
            if len(r) > 64:
                r = r[:64]
            return r
        else:
            return creds[0]
    
    def _safe_merge(self, d1, d2):
        tempd = d1.copy()
        for k, v in d2.items():
            if k in tempd:
                raise Exception(f"{k} is already in dict")
            tempd[k] = v
        return tempd


    def get_list_priority(self, wordlistfile, extensions = None):
        with open(wordlistfile, 'r') as fp:
            cnt = len(fp.readlines())
        if MAX_LIST_SIZE and cnt >= MAX_LIST_SIZE:
            return -1
        if extensions:
            extcnt = len(extensions.split(","))
            if wordlistfile in WEB_WORDLISTS_FILES_HASEXT and not WEB_WORDLISTS_FILES_HASEXT[wordlistfile]:
                logger.debug("Counting lines in file %s times extensions %s", wordlistfile, extcnt)
                cnt *= extcnt
            
        return int(cnt/1000) + 250 # + 250 to run after NMAPs / NetExec Tests
    
    def get_known_hosts(self):
        """Get known hosts ip
        """
        state = State().TEST_STATE.copy()
        return [k for k, _ in state.items() if k != "discovery"]
    
    def get_known_credentials(self):
        """Get knowns credentials, for credentialed enum

        Returns:
            list(tuple): list [(user, password)]
        """
        global CREDENTIALS_FILE
        creds = []
        if not CREDENTIALS_FILE or not os.path.exists(CREDENTIALS_FILE):
            if os.path.exists(os.path.join(State().TEST_WORKING_DIR, "creds.txt")):
                CREDENTIALS_FILE = os.path.join(
                    State().TEST_WORKING_DIR, "creds.txt")
            else:
                return creds
        with open(CREDENTIALS_FILE, "r") as f:
            creds = [x.strip().split(":", 1) for x in f.readlines() if x]
        return creds

    def get_ad_dc_ips(self):
        """Returns all DCs known in state. Host is considered a DC if kerberos and ldap ports opened

        Returns:
            list: list of DCs
        """
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
    
    def get_known_domains(self):
        """Gets the list of all domains known in state

        Returns:
            list: Domain list
        """
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