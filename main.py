#!/usr/bin/env python

# Autoreco
# Tool to automate discovery / enumeration during a pentest assessment
# Usage: See python3 main.py -h

__author__ = "Bastien Migette"

import argparse
import logging
import os
import sys
from datetime import datetime
import autoreco.State

autoreco.State.State().set_working_dir(os.getcwd(), True)

import autoreco.config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-od",
        "--output-dir",
        help="Output Directory. (defaults to current dir)",
        default=None,
    )
    parser.add_argument("-sn", "--subnet", help="Subnet to scan", default=None)
    parser.add_argument(
        "-dn", "--domain", help="DNS Domains to scan", default=[], action='append'
    )
    parser.add_argument("--host", help="Hosts to scan", default=[], action='append')
    parser.add_argument(
        "-t", "--threads", help="Number of threads", default=autoreco.config.NUM_THREADS, type=int
    )
    # parser.add_argument(
    #     "--dns-server", help="DNS Server", default=autoreco.config.DNS_SERVER
    # )
    # Not used atm, because you can just add the dns server via --host, dns enum will be performed against it
    parser.add_argument(
        "-v", "--verbose", help="Verbose Logs (Debug)", action="store_true"
    )
    
    parser.add_argument(
        "-fh", "--force-hosts", help="Process only hosts in args (if resume)", action="store_true"
    )
    parser.add_argument(
        "-tf",
        "--test-filter",
        help="Executes only tests that matches filters, example: *nmap*. fnmatch Format",
        default=[],
        action='append',
    )
    parser.add_argument(
        "-ns",
        "--nmap-speed",
        help="nmap speed (1-5)",
        type=int,
        default=autoreco.config.NMAP_SPEED,
    )

    parser.add_argument(
        "-r",
        "--resume",
        help="Resume from previous working dir",
        default=None,
    )

    parser.add_argument(
        "-rf",
        "--resume-failed",
        help="Resume failed jobs. Default True",
        default=True,
        action="store_true"
    )

    parser.add_argument(
        "-c",
        "--credentials",
        help="Valid Credentials File. Format: user:password",
        default=None,
    )


    parser.add_argument(
        "-mls",
        "--max-list-size",
        type=int,
        help="Do not run tests with list size above this value.",
        default=autoreco.config.MAX_LIST_SIZE,
    )

    parser.add_argument(
        "-rs",
        "--run-scans",
        help="Scans to run, default all. Supported Values: dns,webfiles,webdiscovery,userenum,nmapscan,file,snmp,exploits",
        default=autoreco.config.RUN_SCANS,
    )
        
    parser.add_argument(
        "-nq",
        "--nmap-quick",
        help="Run Only Quick NMAP Scan for discovery",
        default=False,
        action="store_true"
    )
    
    parser.add_argument(
        "-bf",
        "--bruteforce",
        help="Run Brute Force Modules",
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "-bfo",
        "--bruteforce-only",
        help="Run Brute Force Modules Only",
        default=False,
        action="store_true"
    )
    
    parser.add_argument(
        "-hp",
        "--host-priority",
        help="Make a host more prioritized. Format 1.2.3.4=3",
        action='append',
    )
    
    parser.add_argument(
        "-xh",
        "--exclude-hosts",
        help="Exclude hosts, only last digit. For example, to exclude 192.168.1.254, input 254",
        action='append',
    )
    
    
    args = parser.parse_args()
    if args.resume and args.output_dir:
        raise Exception("Please use either resume or output dir")
    
    
    testresume = False
    
    if not args.subnet and not args.domain and not args.host and not args.resume:
        parser.print_help()
        sys.exit(-1)
        
    
    if args.output_dir:
        autoreco.State.State().set_working_dir(args.output_dir)
    elif args.resume:
        if not os.path.isdir(args.resume) or not os.path.exists(os.path.join(args.resume, "state.json")):
            raise Exception(f"state.json not found in dir {args.resume}")
        testresume = True
        autoreco.State.State().set_working_dir(os.path.abspath(args.resume), resume=True)
        autoreco.State.State().load_state()
    else:
        autoreco.State.State().set_working_dir(os.getcwd())    
   
        
    if args.verbose:
        autoreco.config.STDOUT_LOGLEVEL = logging.DEBUG
    if args.exclude_hosts:
        for h in args.exclude_hosts:
            autoreco.config.EXCLUDE_HOSTS.append(h)
    autoreco.config.NUM_THREADS = args.threads
    autoreco.config.NMAP_SPEED = args.nmap_speed
    autoreco.config.TEST_FILTERS = args.test_filter
    autoreco.config.MAX_LIST_SIZE = args.max_list_size
    autoreco.config.RUN_SCANS = args.run_scans
    
    autoreco.State.State().RUNTIME["nmap_quick"] = args.nmap_quick
    
    autoreco.State.State().RUNTIME["host_priority"] = {}
    if args.host_priority:
        for h in args.host_priority:
            parts = h.split("=")
            autoreco.State.State().RUNTIME["host_priority"][parts[0]] = int(parts[1])

    if args.credentials and not os.path.exists(args.credentials):
        raise Exception(f"File doesn't exist: {args.credentials}")
    autoreco.config.CREDENTIALS_FILE = args.credentials
    #autoreco.config.DNS_SERVER = args.dns_server
    # Importing here to make sure we have set config / state properly
    from autoreco.TestRunner import TestRunner
    
    
    autoreco.State.State().RUNTIME["args"] = args
    runner = TestRunner(args.subnet, args.domain, args.host)
    runner.run(testresume, args.resume_failed)


if __name__ == "__main__":
    main()
