# Autoreco
# Tool to automate discovery / enumeration during a pentest assessment
# Author: Bastien Migette
# Usage: See python3 main.py -h

import argparse
import sys
from .logger import logger, WORKING_DIR
def main():
    logger.WORKING_DIR = "#TODO"
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-sc", "--scm", help="Fetch from SCM", action='store_true')
    parser.add_argument(
        "-pn", "--panorama",  help="Use Panorama XML File", action='store_true')
    parser.add_argument(
        "-c", "--config", help="Panorama Running Config XML or the TSF")
    parser.add_argument(
        "-t", "--token", help="SCM Token")
    parser.add_argument(
        "-te", "--tenant", help="Tenant (Panorama Only)")
    parser.add_argument(
         "-lz", "--list-zones", help="List zones", action='store_true')
    parser.add_argument(
        "-ld", "--list-dgs", help="List Device Groups", action='store_true')
    parser.add_argument(
        "-dgs", "--device-groups", help="Comma separated list of DG for panorama. You can also use 'Mobile Users' or 'Remote Network' for SCM")
    parser.add_argument(
        "-v", "--verbose", help="Verbose Output", action='store_true')

    parser.add_argument(
        "-o", "--output", help="Write output to CSV File")
    parser.add_argument(
        "-po", "--output-policies", help="Write policies output to CSV File")

    parser.add_argument("--scm-api-endpoint", help="SCM Api endpoint, for example paas-3.prod.eu", action='store_true')
    parser.add_argument("-usz", "--urlfilter-src-zones", help="Limit URL Filtering adoption to policies matching source zones. Comma separated")
    parser.add_argument("-udz", "--urlfilter-dst-zones", help="Limit URL Filtering adoption to policies matching destination zones. Comma separated")

    args = parser.parse_args()

if __name__ == "__main__":
    main()
