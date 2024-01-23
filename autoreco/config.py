import logging
FILE_LOGGING = True # Log all output to file by default
STDOUT_LOGGING = True # Log all output to stdout by default
NUM_THREADS = 8 # Number of threads
QUEUE_SIZE = 666 # Job queue size
QUEUE_WAIT_TIME = 10 # Time to wait for a queue item. This is time for graceful shutdown essentially
LOGLEVEL = logging.INFO
DEFAULT_PROCESS_TIMEOUT = 600 # Default timeout for a process

##### Modules Specific Config #####

# NETEXEC DISCOVERY MODULE
NETEXEC_DISCOVERY_PROTOCOLS = ["smb", "rdp", "wmi"]

# NMAP HOST SCAN OPTIONS
NMAP_DEFAULT_TCP_PORT_OPTION = "-p-"
NMAP_DEFAULT_UDP_PORT_OPTION = "--top-ports 1000"
NMAP_HOSTSCAN_OPTIONS = "-sC -sV -Pn -T3 --version-all -O --script-timeout 60"