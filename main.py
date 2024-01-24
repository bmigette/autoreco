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

autoreco.state.set_working_dir(os.getcwd(), True)

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
        "-dn", "--domain", help="DNS Domains to scan", default=[], nargs="*"
    )
    parser.add_argument("--host", help="Hosts to scan", default=[], nargs="*")
    parser.add_argument(
        "-t", "--threads", help="Number of threads", default=autoreco.config.NUM_THREADS
    )
    parser.add_argument(
        "--dns-server", help="DNS Server", default=autoreco.config.DNS_SERVER
    )
    parser.add_argument(
        "-v", "--verbose", help="Verbose Logs (Debug)", action="store_true"
    )
    parser.add_argument(
        "-tf",
        "--test-filter",
        help="Executes only tests that matches filters, example: *nmap*. fnmatch Format",
        default=[],
        nargs="*",
    )
    parser.add_argument(
        "-ns",
        "--nmap-speed",
        help="nmap speed (1-5)",
        type=int,
        default=autoreco.config.NMAP_SPEED,
    )

    # add option fod DNS Server

    args = parser.parse_args()
    if args.output_dir:
        autoreco.state.set_working_dir(args.output_dir)
    if args.verbose:
        autoreco.config.LOGLEVEL = logging.DEBUG

    autoreco.config.NUM_THREADS = args.threads
    autoreco.config.NMAP_SPEED = args.nmap_speed
    autoreco.config.TEST_FILTERS = args.test_filter
    autoreco.config.DNS_SERVER = args.dns_server
    # Importing here to make sure we have set config / state properly
    from autoreco.TestRunner import TestRunner

    runner = TestRunner(args.subnet, args.domain, args.host)
    runner.run()


if __name__ == "__main__":
    main()
