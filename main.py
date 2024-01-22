#!/usr/bin/env python

# Autoreco
# Tool to automate discovery / enumeration during a pentest assessment
# Author: Bastien Migette
# Usage: See python3 main.py -h

import argparse
import logging
import os
import autoreco.state
autoreco.state.WORKING_DIR = os.getcwd()
import autoreco.config

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-od", "--output-dir", help="Output Directory. (defaults to current dir)", default=None)
    parser.add_argument(
        "-sn", "--subnet",  help="Subnet to scan", default=None)
    parser.add_argument(
        "-dn", "--domain",  help="DNS Domain to scan", default=None)
    parser.add_argument(
        "-v", "--verbose",  help="Verbose Logs (Debug)", action='store_true')

    parser.add_argument("--scm-api-endpoint", help="SCM Api endpoint, for example paas-3.prod.eu", action='store_true')


    args = parser.parse_args()
    if args.output_dir:
        autoreco.state.WORKING_DIR = args.output_dir
    if args.verbose:
        autoreco.config.LOGLEVEL = logging.DEBUG
    
    # Importing here to make sure we have set config / state properly
    from autoreco.TestRunner import TestRunner
    runner = TestRunner(args.subnet, args.domain)
    runner.run()
    

if __name__ == "__main__":
    main()
