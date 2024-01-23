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
NMAP_DEFAULT_UDP_PORT_OPTION = "--top-ports 150"
NMAP_SPEED = 5
NMAP_MAX_HOST_TIME = "15m" #Max time per host for NMAP, see https://nmap.org/book/man-performance.html
NMAP_TCP_HOSTSCAN_OPTIONS = f"-sC -sV -Pn -T{NMAP_SPEED} --version-all -O --script-timeout 60"
NMAP_UDP_HOSTSCAN_OPTIONS = f"-sC -sV -Pn -T{NMAP_SPEED} --version-all -O --script-timeout 60 --version-intensity 3"