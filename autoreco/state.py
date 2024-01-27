
import threading
statelock = threading.Lock()
import os
from datetime import datetime
import json
"""
State module. The variables below are global to the scope of the script
"""

"""
Accessing below variable should always get the statelock first
ex:
with state.statelock:
    pass
    
See https://superfastpython.com/lock-an-object-in-python/#Lock_an_Object
"""
TEST_STATE = {}

TEST_DATE = None
TEST_DATE_STR = None
WORKING_DIR = None
TEST_WORKING_DIR = None

domainlock = threading.Lock()
KNOWN_DOMAINS = []

def set_working_dir(dir, nocreate = False, resume = False):
    global TEST_DATE, TEST_DATE_STR, WORKING_DIR, TEST_WORKING_DIR    
    if not resume:
        WORKING_DIR = dir
        TEST_DATE = datetime.now()
        TEST_DATE_STR = TEST_DATE.strftime("%Y_%m_%d__%H_%M_%S")
        TEST_WORKING_DIR = os.path.join(WORKING_DIR, f"autoreco_{TEST_DATE_STR}")
        if not nocreate:
            os.makedirs(TEST_WORKING_DIR, exist_ok=True)
    else:
        TEST_WORKING_DIR = dir
        WORKING_DIR = os.path.abspath(os.path.join(TEST_WORKING_DIR, os.pardir))
        TEST_DATE_STR = TEST_WORKING_DIR.split("autoreco_")[1].replace("/", "")
        
        
        
def load_state():
    global TEST_STATE, KNOWN_DOMAINS
    with statelock:
        with open(os.path.join(TEST_WORKING_DIR, "state.json")) as f:
            TEST_STATE = json.loads(f.read())
    with domainlock:
        with open(os.path.join(TEST_WORKING_DIR, "domains.json")) as f:
            KNOWN_DOMAINS = json.loads(f.read())