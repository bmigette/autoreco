# Intro
This tool will iteratively run various discovery/enumeration tools in a pentesting scenario.
It will start with subnet scan using netexec smb / nmap ping (if you specified --subnet argment)
Then for each host that is up, it will start scanning open tcp / udp ports with NMAP, then it will start specific discovery/enumeration jobs based on discovered open ports.
For example:
- Web server will be scanned with GoBuster and FFUF to discover files, folders, and vhosts
- AD DCs will trigger a kerbrute / rid brute with netexec
- SMB Servers will trigger nmap smb scripts + spider_plus plugin of netexec
- DNS Servers will trigger GoBuster dns scan
- ...

The process is iterative, meaning if a new host or vhost is discovered for example (by FFUF Vhost / GoBuster DNS), we will ran another set of GoBuster / FFUF scan against this new vhost.
If a new domain is discovered, it will try vhosts based on the known hostnames of a webserver and attempt to scan again with this new domain
etc...

The script uses Multiple Threads (configurable) with a PriorityQueue, allowing smaller/faster Jobs to be executed first (to avoid blocking progress with lot of large wordlists)

Note: known domains can be specified manually with --domain, or learnt automatically by netexec

# Requirements

NMAP will be run as sudo. You user should be able to do "sudo nmap" without being prompted (add it in your sudoers file)
```
userid ALL=(ALL) NOPASSWD:nmap_path
```

Tools that needs to be installed (and in system PATH):
- netexec
- gobuster
- ffuf
- nmap
- enum4linux-ng
- kerbrute
- feroxbuster
- wkhtmltoimage
- medusa

Additional Tools
 
- Firejail [[https://github.com/netblue30/firejail]]: (Needed to force DNS Server for some tools, netexec in ldap mode for example)

TODO: Remove when this is released https://github.com/Pennyw0rth/NetExec/commit/2790236622eea56fb221833894ca765dc7e7a700

# Installation
```
pip install -r requirements.txt
```

# Configuration

There's a few hardcoded path in the config.py that matches default path for a Kali Linux installation. This need to be adjusted for your system.
Other options can also be fine tuned in this file.

# Usage

```
python main.py -h
usage: main.py [-h] [-od OUTPUT_DIR] [-sn SUBNET] [-dn [DOMAIN ...]] [--host [HOST ...]] [-t THREADS] [-v] [-tf [TEST_FILTER ...]] [-ns NMAP_SPEED] [-e RESUME]

options:
  -h, --help            show this help message and exit
  -od OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Output Directory. (defaults to current dir)
  -sn SUBNET, --subnet SUBNET
                        Subnet to scan
  -dn DOMAIN, --domain DOMAIN
                        DNS Domains to scan
  --host HOST           Hosts to scan
  -t THREADS, --threads THREADS
                        Number of threads
  -v, --verbose         Verbose Logs (Debug)
  -fh, --force-hosts    Process only hosts in args (if resume)
  -tf TEST_FILTER, --test-filter TEST_FILTER
                        Executes only tests that matches filters, example: *nmap*. fnmatch Format
  -ns NMAP_SPEED, --nmap-speed NMAP_SPEED
                        nmap speed (1-5)
  -r RESUME, --resume RESUME
                        Resume from previous working dir
  -rf, --resume-failed  Resume failed jobs. Default True
  -c CREDENTIALS, --credentials CREDENTIALS
                        Valid Credentials File. Format: user:password
  -mls MAX_LIST_SIZE, --max-list-size MAX_LIST_SIZE
                        Do not run tests with list size above this value.
  -rs RUN_SCANS, --run-scans RUN_SCANS
                        Scans to run, default all. Supported Values: dns,webfiles,webdiscovery,userenum,nmapscan,file,snmp,exploits
  -nq, --nmap-quick     Run Only Quick NMAP Scan for discovery
  -bf, --bruteforce     Run Brute Force Modules
  -bfo, --bruteforce-only
                        Run Brute Force Modules Only
  -hp HOST_PRIORITY, --host-priority HOST_PRIORITY
                        Make a host more prioritized. Format 1.2.3.4=3
```

## Domain Discovery
To use domain discovery, the script needs to detect a working DNS Server. You can add one with --host. For this to work, nmap needs to be able to detect dns service running.

# Examples
```
python main.py --subnet 192.168.1.0/24
python main.py --host 192.168.1.1 --domain test.com
```

## Resuming a scan
The following command will attempt to resume a scan. The resume-failed option allows to retry all jobs that are not successful (Error, Stopped, ...)
```
python main.py --resume /path/to/autoreco_2024_xxxx --resume-failed
```

## Run additional jobs once you have valid credentials
creds.txt file format:
>user:password
```
python main.py --resume /path/to/autoreco_2024_xxxx --credentials /path/to/creds.txt
```

Note that by default, the tool will look into creds.txt file in the working dir (/path/to/autoreco_2024_xxxx) and if it exists, use this credentials, meaning you can add credentials to a running scan.

You can also put a NTLM Hash as password, it will be used where supported & applicable

## Running a Scan over a Pivot or slow network
If your network connection to target is slow or unreliable, I'd recommennd lowering number of threads and list size:
```
autoreco -t 3 -mls 500000 --subnet 192.168.1.0/24 
```

## Scan a subnet with a host in priority
If you want to scan a whole subnet, but you want to want to start in priority with a specific host, you can use args like this
```
autoreco -t 3 -mls 500000 --subnet 192.168.1.0/24 --host-priority 192.168.1.10=10
```

This will make this host priority 10x more than others.
To keep in mind, each job has a priority, which depends on various factors including the size of the list (if any) used for the job. This make the priority higher by the factor specified in argument, but does not guarantee all jobs for this host will run first.

## Bruteforce
Run bruteforces tests for an existing project
```
autoreco --resume autoreco_2024_03_21__17_31_35 --bruteforce-only
```

Run bruteforces tests for an existing project, on a specific host
```
autoreco --resume autoreco_2024_03_21__17_31_35 --bruteforce-only --host 1.2.3.4 --force-hosts
```

# Notes
This is absolutely not stealth. Before scanning any system, make sure you are authorized to do it.

# Known Issues

Quitting with CTRL+C will throw a bunch of exceptions, but should eventually quit.