import logging

FILE_LOGGING = True  # Log all output to file by default
FILE_LOGGING_DEBUG = True # Log debug to file
STDOUT_LOGGING = True  # Log all output to stdout by default
NUM_THREADS = 8  # Number of threads
QUEUE_SIZE = 666  # Job queue size
QUEUE_WAIT_TIME = (
    10  # Time to wait for a queue item. This is time for graceful shutdown essentially
)
STDOUT_LOGLEVEL = logging.INFO
DEFAULT_PROCESS_TIMEOUT = 900  # Default timeout for a process
DEFAULT_IDLE_TIMEOUT = 180  # Default timeout for a idle process
DEFAULT_LONGPROCESS_TIMEOUT = 60*60*2  # Default timeout for a long process, not used atm
WATCHDOG_INTERVAL = 120
WATCHDOG_SLEEP_INTERVAL = 10  # for stopping
TEST_FILTERS = []  # execute tests matching these filters only
DNS_SERVER = None # Not used atm
DEFAULT_MAX_OUTPUT = 10000 # Max len of command output
RUN_SCANS = "all" #dns,webfiles,webdiscovery,userenum,...


##### Modules Specific Config #####

# NETEXEC DISCOVERY MODULE
NETEXEC_DISCOVERY_PROTOCOLS = ["smb", "rdp", "wmi"]
NETEXEC_USERENUM_PROTOCOLS = ["smb", "rdp", "wmi", "winrm", "ldap"]

# NMAP HOST SCAN OPTIONS
NMAP_DEFAULT_TCP_PORT_OPTION = "-p-"
NMAP_DEFAULT_UDP_PORT_OPTION = "--top-ports 150"
NMAP_SPEED = 4
NMAP_MAX_HOST_TIME = (
    20  # Max time per host for NMAP (in minutes), see https://nmap.org/book/man-performance.html
)
NMAP_TCP_HOSTSCAN_OPTIONS = (
    f"-sT -sC -sV -Pn -T{NMAP_SPEED} --version-all -O --script-timeout 60"
) # Setting to -sT because otherwise does not work thru proxy
NMAP_UDP_HOSTSCAN_OPTIONS = f"-sC -sV -Pn -T{NMAP_SPEED} --version-all -O --script-timeout 60 --version-intensity 3"

# Skip tests using a list that is above this size (example 250000)
MAX_LIST_SIZE = None

# GOBUSTER / FFUF Options
WEB_WORDLISTS = {
    "dir": [
        "/usr/share/wordlists/seclists/Discovery/Web-Content/quickhits.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        #"/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",        
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt",
    ],
    "vhost": [        
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt", 
        #"/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt",
    ],
    "dns": [        
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt", 
        #"/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt",
    ],
    "files": [
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"
    ]
}


WEB_WORDLISTS_FILES_HASEXT = {
    "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt" : True,
    "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt": False
}
# See https://gist.github.com/Anon-Exploiter/be23b48bc2ec8dd16b5fd8cdcc3e4188
#GOBUSTER_FILE_EXT = "pdf,csv,txt,html,htm,php,c,exe,php5,sh,sql,xml,asp,aspx"
GOBUSTER_FILE_EXT = "pdf,csv,txt,html,htm,php,sh,sql,xml"

FFUF_MAX_VHOST = 50 # If more than this vhost found, ignoring, could a site responding to all vhosts
FFUF_MAX_SAME_WORDS = 2 # Ignore results that have same number of words, if above this

# UserEnum
USERENUM_LISTS = [
    "/usr/share/statistically-likely-usernames/jsmith.txt",
    "/usr/share/statistically-likely-usernames/service-accounts.txt",
    "/usr/share/statistically-likely-usernames/john.smith.txt",
    "/usr/share/statistically-likely-usernames/john.txt",
    #"/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt" # More for web usernames
]

# SNMP
SNMP_WORDLISTS = [
    "/usr/share/wordlists/seclists/Discovery/SNMP/snmp-onesixtyone.txt"
]

CREDENTIALS_FILE = None

USE_SYSTEM_RESOLVER = False