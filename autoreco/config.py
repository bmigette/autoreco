import logging

FILE_LOGGING = True  # Log all output to file by default
FILE_LOGGING_DEBUG = True  # Log debug to file
STDOUT_LOGGING = True  # Log all output to stdout by default
NUM_THREADS = 6  # Number of threads
QUEUE_SIZE = 666  # Job queue size
QUEUE_WAIT_TIME = (
    10  # Time to wait for a queue item. This is time for graceful shutdown essentially
)
STDOUT_LOGLEVEL = logging.INFO
DEFAULT_PROCESS_TIMEOUT = 900  # Default timeout for a process
DEFAULT_IDLE_TIMEOUT = 180  # Default timeout for a idle process
# Default timeout for a long process, not used atm
DEFAULT_LONGPROCESS_TIMEOUT = 60*60*2
WATCHDOG_INTERVAL = 60
WATCHDOG_SLEEP_INTERVAL = 10  # for stopping
TEST_FILTERS = []  # execute tests matching these filters only
DNS_SERVER = None  # Not used atm
DEFAULT_MAX_OUTPUT = 10000  # Max len of command output
RUN_SCANS = "all"  # dns,webfiles,webdiscovery,userenum,...

MAX_JOB_PER_HOST = 3
MAX_JOB_PER_HOST_PORT = 1

##### Modules Specific Config #####

# NETEXEC DISCOVERY MODULE
NETEXEC_DISCOVERY_PROTOCOLS = ["smb", "rdp", "wmi"]
NETEXEC_USERENUM_PROTOCOLS = ["smb", "rdp", "wmi", "winrm", "ldap"]

# NMAP HOST SCAN OPTIONS
NMAP_DEFAULT_TCP_PORT_OPTION = "-p-"
NMAP_DEFAULT_UDP_PORT_OPTION = "--top-ports 150"
NMAP_DEFAULT_TCP_QUICK_PORT_OPTION = "--top-ports 200"
NMAP_DEFAULT_TCP_SUBNET_PORT_OPTION = "--top-ports 50"
NMAP_SPEED = 4
NMAP_MAX_HOST_TIME = (
    # Max time per host for NMAP (in minutes), see https://nmap.org/book/man-performance.html
    20
)
NMAP_TCP_HOSTSCAN_OPTIONS = (
    f"-sT -sC -sV -Pn -T{NMAP_SPEED} --version-all -O --script-timeout 60"
)  # Setting to -sT because otherwise does not work thru proxy
NMAP_UDP_HOSTSCAN_OPTIONS = f"-sC -sV -Pn -T{NMAP_SPEED} --version-all -O --script-timeout 60 --version-intensity 3"

# Skip tests using a list that is above this size (example 250000)
MAX_LIST_SIZE = None

# GOBUSTER / FFUF Options

HTTP_IGNORE_PORTS = [5985, 5986, 47001]  #  Ignoring MS WinRM & MS API
HTTP_REQ_TIMEOUT_SEC = 20

EXCLUDE_HOSTS = ["1", "254"]

WEB_WORDLISTS = {
    "dir": [
        "/usr/share/wordlists/seclists/Discovery/Web-Content/quickhits.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        # "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        #"/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt",
    ],
    "vhost": [
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        # "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt",
        #"/usr/share/wordlists/seclists/Discovery/DNS/combined_subdomains.txt"
    ],
    "dns": [
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        # "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt",
        #"/usr/share/wordlists/seclists/Discovery/DNS/combined_subdomains.txt"
    ],
    "files": [
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"
    ],
    "recursive": [
        "/usr/share/seclists/Discovery/Web-Content/big.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"
    ]
}


WEB_WORDLISTS_FILES_HASEXT = {
    "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt": True,
    "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt": False
}
# See https://gist.github.com/Anon-Exploiter/be23b48bc2ec8dd16b5fd8cdcc3e4188
# GOBUSTER_FILE_EXT = "pdf,csv,txt,html,htm,php,c,exe,php5,sh,sql,xml,asp,aspx"
GOBUSTER_FILE_EXT = "pdf,csv,txt,html,htm,php,sh,sql,xml"

# If more than this vhost found, ignoring, could a site responding to all vhosts
FFUF_MAX_VHOST = 50
FFUF_MAX_SAME_WORDS = 2  # Ignore results that have same number of words, if above this
FFUF_EXTLIST = ".asp,.aspx,.bat,.c,.cgi,.exe,.htm,.html,.inc,.jsp,.log,.php,.phps,.phtml,.pl,.reg,.sh,.zsh,.shtml,.sql,.txt,.xml,.yml,.css,.js,.csv,.pdf"
FFUF_STATUS_EXCLUDE = "400,404"
# UserEnum
USERENUM_LISTS = [
    "/usr/share/statistically-likely-usernames/jsmith.txt",
    "/usr/share/statistically-likely-usernames/service-accounts.txt",
    "/usr/share/statistically-likely-usernames/john.smith.txt",
    "/usr/share/statistically-likely-usernames/john.txt",
    # "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt" # More for web usernames
]

# SNMP
SNMP_WORDLISTS = [
    "/usr/share/wordlists/seclists/Discovery/SNMP/snmp-onesixtyone.txt"
]

CREDENTIALS_FILE = None

USE_SYSTEM_RESOLVER = False


# FEROXBUSTER
FEROXBUSTER_WORDLISTS = [ #"/usr/share/seclists/Discovery/Web-Content/big.txt",
                         "/usr/share/wordlists/dirb/common.txt",
                         "/usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt"]
FEROXBUSTER_EXTLIST = "asp,aspx,bat,c,cgi,exe,htm,html,inc,jsp,log,php,phtml,pl,reg,sh,shtml,sql,txt,xml,yml,pdf,csv"
FEROXBUSTER_STATUS = "200,201,202,203,204,301,302,307,401,403,405,407,405,500,501,502,503,505"  #  NOT USED
FEROXBUSTER_STATUS_EXCLUDE = "404,400"
FEROXBUSTER_THREADS = 30


# BRUTEFORCE
BRUTEFORCE_USERLISTS = [
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
]

BRUTEFORCE_PASSWORDLISTS = [
    "/usr/share/seclists/Passwords/500-worst-passwords.txt",
    "/usr/share/seclists/Passwords/2023-200_most_used_passwords.txt",
    "/usr/share/seclists/Passwords/cirt-default-passwords.txt",
]
