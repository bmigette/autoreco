WORKING_DIR = None
import threading
statelock = threading.Lock()

"""
Accessing below variable should always get the statelock first
ex:
with state.statelock:
    pass
    
See https://superfastpython.com/lock-an-object-in-python/#Lock_an_Object
"""
TEST_STATE = {}

datelock = threading.Lock()
TEST_DATE = None
TEST_DATE_STR = None