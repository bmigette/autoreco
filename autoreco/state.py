WORKING_DIR = None
import threading
statelock = threading.Lock()

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