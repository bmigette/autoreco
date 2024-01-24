import logging

FILE_LOGGING = True  # Log all output to file by default
STDOUT_LOGGING = True  # Log all output to stdout by default
NUM_THREADS = 8  # Number of threads
QUEUE_SIZE = 666  # Job queue size
QUEUE_WAIT_TIME = (
    10  # Time to wait for a queue item. This is time for graceful shutdown essentially
)
LOGLEVEL = logging.INFO
DEFAULT_PROCESS_TIMEOUT = 600  # Default timeout for a process
WATCHDOG_INTERVAL = 120
WATCHDOG_SLEEP_INTERVAL = 10  # for stopping
TEST_FILTERS = []  # execute tests matching these filters only
DNS_SERVER = None

##### Modules Specific Config #####

# NETEXEC DISCOVERY MODULE
NETEXEC_DISCOVERY_PROTOCOLS = ["smb", "rdp", "wmi"]

# NMAP HOST SCAN OPTIONS
NMAP_DEFAULT_TCP_PORT_OPTION = "-p-"
NMAP_DEFAULT_UDP_PORT_OPTION = "--top-ports 150"
NMAP_SPEED = 4
NMAP_MAX_HOST_TIME = (
    "15m"  # Max time per host for NMAP, see https://nmap.org/book/man-performance.html
)
NMAP_TCP_HOSTSCAN_OPTIONS = (
    f"-sC -sV -Pn -T{NMAP_SPEED} --version-all -O --script-timeout 60"
)
NMAP_UDP_HOSTSCAN_OPTIONS = f"-sC -sV -Pn -T{NMAP_SPEED} --version-all -O --script-timeout 60 --version-intensity 3"


# GOBUSTER Options
GOBUSTER_WORDLISTS = {
    "dir": [
        "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/quickhits.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
    ],
    "vhost": [
        "/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt", 
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
    ],
    "dns": [
        "/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt", 
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
    ],
    "files": [
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt"
    ]
}

GOBUSTER_FILE_EXT = "pdf,csv,txt,html,php,c,exe,php5,sh,sql,xml"
