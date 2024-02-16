from .UserEnumModuleBase import UserEnumModuleBase
from ...config import DEFAULT_PROCESS_TIMEOUT
from ...logger import logger
from ...utils import is_ip, remove_ansi_escape_chars

class Kerbrute(UserEnumModuleBase):
    """Class to run NetExec against a single host"""

    def run(self):
        if not is_ip(self.target):
            raise ValueError("Target should be an IP: %s", self.target)

        logfile = self.get_log_name("log")
        cmdfile =  self.get_log_name("cmd")

        domain = self.args["domain"]
        w = self.args["wordlist"]
        
        logger.info("Starting kerbrute against %s", self.target)        
        # `kerbrute userenum -d manager.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.11.236`
        self.command = f"kerbrute userenum -d {domain} {w} --dc {self.target} -o {logfile}"
        # TODO Implement Kerbrute output parsing, and make it a realtime output: Cannot do!! No useful output
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile, logoutput=logfile, timeout=DEFAULT_PROCESS_TIMEOUT*2)
        try:
            self._parse_output(self.output)
        except Exception as e:
            logger.error("Error when parsing output for Kerbrute: %s", e, exc_info=True)
        
    def _parse_output(self, output):
        #output = remove_ansi_escape_chars(output)
        pass

"""
2024/02/15 23:22:08 >  Using KDC(s):[0m
2024/02/15 23:22:08 >  	172.16.212.10:88
[0m
[32m2024/02/15 23:22:08 >  [+] VALID USERNAME:	 joe@medtech.com[0m
[32m2024/02/15 23:22:09 >  [+] VALID USERNAME:	 mario@medtech.com[0m
[32m2024/02/15 23:22:10 >  [+] VALID USERNAME:	 leon@medtech.com[0m
[32m2024/02/15 23:22:26 >  [+] VALID USERNAME:	 yoshi@medtech.com[0m
[31m2024/02/15 23:22:28 >  [!] kesha@medtech.com - failed to communicate with KDC. Attempts made with UDP (error sending to a KDC: error sneding to 172.16.212.10:88: sending over UDP failed to 172.16.212.10:88: read udp 192.168.1.66:60745->172.16.212.10:88: i/o timeout) and then TCP (error in getting a TCP connection to any of the KDCs)[0m
2024/02/15 23:22:29 >  Done! Tested 4779 usernames (4 valid) in 21.420 seconds[0m
"""