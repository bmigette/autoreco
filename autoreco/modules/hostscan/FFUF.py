from ..ModuleInterface import ModuleInterface
from ...logger import logger
from ...config import FFUF_MAX_VHOST, FFUF_MAX_SAME_WORDS, HTTP_REQ_TIMEOUT_SEC
from ..common.parsers import parse_ffuf_progress

from ...TestHost import TestHost

import json

# ffuf -H "Host: FUZZ.forestsave.lab" -ac -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://forestsave.lab


class FFUF(ModuleInterface):
    """Class to run FFUF against a single host"""

    def run(self):
        self.web = True
        url = "-u " + self.args["url"]
        if "fuzz_url" in self.args:
            url += "/FUZZ"
        w = self.args["wordlist"]
        mode = "vhost"
        if "mode" in self.args:
            mode = self.args["mode"]
        vhost = ""
        if mode == "vhost":
            domain = self.args["domain"]
            vhost = f"-H 'Host: FUZZ.{domain}'"
        else:
            if "host" in self.args:
                vhost = "-H 'Host: " + self.args["host"] + "'"

        output_log = self.get_log_name(
            "", argusekey=["extensions", "extra_args"], folder="FFUF")
        output_log_json = f"{output_log}.json"
        output_log_cmd = f"-o {output_log} -of all"

        cmdlog = self.get_log_name(
            ".cmd", argusekey=["extensions", "extra_args"], folder="FFUF")
        stdout_log = self.get_log_name(
            ".log", argusekey=["extensions", "extra_args"], folder="FFUF")

        filter_arg = "-ac"
        if "filter_arg" in self.args: # https://www.acceis.fr/ffuf-advanced-tricks/
            filter_arg = self.args["filter_arg"]
            filter_arg = "-fr '/\..*' -mc all " + filter_arg

        extra_args = ""
        if "extra_args" in self.args:
            extra_args = " ".join(self.args["extra_args"])

        ext = ""
        if "extensions" in self.args:
            ext = "-e " + self.args["extensions"]
        cmd = f"ffuf {filter_arg} -noninteractive -w {w}:FUZZ {url} {ext} -timeout {HTTP_REQ_TIMEOUT_SEC} {vhost} {extra_args} {output_log_cmd}"
        logger.debug("Executing FFUF command %s", cmd)
        ret = self.get_system_cmd_outptut(
            cmd, logoutput=stdout_log, logcmdline=cmdlog, realtime=True, progresscb=parse_ffuf_progress)
        hostobj = TestHost(self.target)
        if mode == "vhost":
            self.parse_scan_hosts(output_log_json, hostobj)

    def parse_scan_hosts(self, output_log, hostobj):
        """Parse scanned host file

        Args:
            output_log (str): json file to read
            hostobj (TestHost): TestHost object
        """
        try:
            domain = self.args["domain"]
            with open(output_log, "r") as f:
                data = json.loads(f.read())
            if len(data["results"]) > FFUF_MAX_VHOST:
                self.status = "error"
                logger.warn("Too many results in FFUF Vhosts (%s) scan for host %s, assuming false positive", len(
                    data["results"]), self.args["url"])
                return

            if len(data["results"]) < 1:
                self.move_to_empty_files()
                return

            words = {}
            # Auto Calibration sometime gives duplicate results because size is different. Haven't foudn a way to filter on words automatically
            for r in data["results"]:
                if r["words"] in words:
                    words[r["words"]] += 1
                else:
                    words[r["words"]] = 1

            for r in data["results"]:
                host = r["host"]
                if words[r["words"]] > FFUF_MAX_SAME_WORDS:
                    logger.warn(
                        "Ignoring vhost %s because seems false positive based on similar word result %s", host, words[r["words"]])
                    continue
                if domain not in host:
                    host = f"{host}.{domain}"
                hostobj.add_hostname(host)
        except Exception as e:
            self.status = "error"
            logger.error("Error when parsing FFUF output file %s: %s",
                         output_log, e, exc_info=True)
