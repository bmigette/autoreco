# Intro
This tool will iteratively run various discovery/enumeration tools in a pentesting scenario.
It will start with scanning open tcp / udp ports with NMAP, then it will start specific tests based on discovered open ports.
For example:
- Web server will be scanned with GoBuster and FFUF to discover files, folders, and vhosts
- AD DCs will trigger a kerbrute / rid brute with netexec
- SMB Servers will trigger nmap smb scripts + spider_plus plugin of netexec
- DNS Servers will trigger dnsenum / sublist3r #TODO fix
- ...

The process is iterative, meaning if a new vhost is discovered for example, we will ran another set of GoBuster / FFUF tests against this new vhost.
If a new domain is discovered, we will generate vhosts based on the known hostnames of a webserver and attempt to scan again.
etc...

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

# Installation
```
pip install -r requirements.txt
```

# Configuration
There's a few hardcoded path in the config.py that matches default path for a Kali Linux installation. Might need to be adjusted for your system
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
  -dn [DOMAIN ...], --domain [DOMAIN ...]
                        DNS Domains to scan
  --host [HOST ...]     Hosts to scan
  -t THREADS, --threads THREADS
                        Number of threads
  -v, --verbose         Verbose Logs (Debug)
  -tf [TEST_FILTER ...], --test-filter [TEST_FILTER ...]
                        Executes only tests that matches filters, example: *nmap*. fnmatch Format
  -ns NMAP_SPEED, --nmap-speed NMAP_SPEED
                        nmap speed (1-5)
  -e RESUME, --resume RESUME
                        Resume from previous working dir
```

# Notes
This is absolutely not stealth. Before scanning any system, make sure you are authorized to do it.