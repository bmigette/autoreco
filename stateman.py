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

# TODO: Implement state cleaner
# TODO: Remove tests from state
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-od",
        "--output-dir",
        help="Output Directory. (defaults to current dir)",
        default=None,
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
    
        
    args = parser.parse_args()
    if args.resume and args.output_dir:
        raise Exception("Please use either resume or output dir")
    
    
    if args.credentials and not os.path.exists(args.credentials):
        raise Exception(f"File doesn't exist: {args.credentials}")
    autoreco.config.CREDENTIALS_FILE = args.credentials
    #autoreco.config.DNS_SERVER = args.dns_server
    # Importing here to make sure we have set config / state properly
    from autoreco.TestRunner import TestRunner

    runner = TestRunner(args.subnet, args.domain, args.host)
    runner.run("testre", args.resume_failed)


if __name__ == "__main__":
    main()
