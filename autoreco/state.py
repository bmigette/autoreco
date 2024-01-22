WORKING_DIR = None

import threading
statelock = threading.Lock()

"""
Accessing below variable should always get the statelock first
ex:
with state.statelock:
    pass
    
See https://superfastpython.com/lock-an-object-in-python/#Lock_an_Object
Format is {
    "1.2.3.4": {
        "ip": "1.2.3.4",
        "hostnames": ["host.xxx.com"],
        "os_family": "windows",
        "os_version": "windows 10 xxx",
        "services": ["http", "dns"],
        "tcp_ports": [80, 8080, 443],
        "service_ports": {
            "http": [80, 8080]
        },
        tests_state : {
            "xxxx" : {
                "module": "moduleName",
                "state": "done"
            }
        }
    }
}
"""
TEST_STATE = {}