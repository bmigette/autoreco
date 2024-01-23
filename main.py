#!/usr/bin/env python

# Autoreco
# Tool to automate discovery / enumeration during a pentest assessment
# Usage: See python3 main.py -h

__author__ = "Bastien Migette"

import argparse
import logging
import os
from datetime import datetime
import autoreco.state

autoreco.state.WORKING_DIR = os.getcwd()
autoreco.state.TEST_DATE = datetime.now()
autoreco.state.TEST_DATE_STR = autoreco.state.TEST_DATE.strftime("%Y_%m_%d__%H_%M_%S")
import autoreco.config


def check_privileges():
    if not os.environ.get("SUDO_UID") and os.geteuid() != 0:
        raise PermissionError(
            "You need to run this script with sudo or as root (needed for some nmap options)"
        )


def main():
    check_privileges()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-od",
        "--output-dir",
        help="Output Directory. (defaults to current dir)",
        default=None,
    )
    parser.add_argument("-sn", "--subnet", help="Subnet to scan", default=None)
    parser.add_argument("-dn", "--domain", help="DNS Domain to scan", default=None)
    parser.add_argument("-h", "--host", help="Host to scan", default=None)
    parser.add_argument(
        "-t", "--threads", help="number of threads", default=autoreco.config.NUM_THREADS
    )
    parser.add_argument(
        "-v", "--verbose", help="Verbose Logs (Debug)", action="store_true"
    )
    parser.add_argument(
        "-ns",
        "--nmap-speed",
        help="nmap speed (1-5)",
        type=int,
        default=autoreco.config.NMAP_SPEED,
    )

    #add option for Process timeout
    
    args = parser.parse_args()
    if args.output_dir:
        autoreco.state.WORKING_DIR = args.output_dir
    if args.verbose:
        autoreco.config.LOGLEVEL = logging.DEBUG

    autoreco.config.NUM_THREADS = args.num_threads
    autoreco.config.NMAP_SPEED = args.nmap_speed
    # Importing here to make sure we have set config / state properly
    from autoreco.TestRunner import TestRunner

    runner = TestRunner(args.subnet, args.domain, args.host)
    runner.run()


if __name__ == "__main__":
    main()
