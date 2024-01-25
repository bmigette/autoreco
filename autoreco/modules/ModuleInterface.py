from abc import ABC, abstractmethod
from ..logger import logger
from ..state import TEST_WORKING_DIR, TEST_DATE, TEST_DATE_STR
from ..config import DEFAULT_PROCESS_TIMEOUT
import os
from subprocess import STDOUT, check_output, CalledProcessError, TimeoutExpired
import shlex
from ..TestHost import TestHost
import re
from pathlib import Path


class ModuleInterface(ABC):
    """Generic modules functions"""

    def __init__(self, testid, target, module_name, args={}):
        self.status = "notstarted"
        self.args = args
        self.testid = testid
        self.target = target
        self.module_name = module_name
        if TestHost.is_ip(target):
            self.ip = target
        else:
            self.ip = None

    def get_host_obj(self, ip: str) -> TestHost:
        return TestHost(ip)

    def get_system_cmd_outptut(
        self,
        command: str,
        timeout: int = DEFAULT_PROCESS_TIMEOUT,
        logoutput=None,
        logcmdline=None,
    ):
        """Run a system command and get the output

        Args:
            command (str): command line
            timeout (int, optional): Process timeout. Defaults to DEFAULT_PROCESS_TIMEOUT.

        Returns:
            str: command output
        """
        if logcmdline:
            try:
                with open(logcmdline, "a") as f:
                    f.write(command)
            except Exception as e:
                logger.error("Could not write cmd to file %s: %s", logoutput, e)
        if not isinstance(command, list):
            command = shlex.split(command)
        logger.debug("Executing command %s in module %s...", command, self.module_name)
        try:
            ret = check_output(command, stderr=STDOUT, timeout=timeout)
        except CalledProcessError as ce:
            if type(ce.cmd).__name__ == "bytes":
                ce.cmd = ce.cmd.decode("utf-8")
            if type(ce.output).__name__ == "bytes":
                ce.output = ce.output.decode("utf-8")
            if type(ce.stderr).__name__ == "bytes":
                ce.stderr = ce.stderr.decode("utf-8")
            logger.error(
                "Error in command %s: code: %s, stdout:\n%s \nstderr:\n%s",
                ce.cmd,
                ce.returncode,
                ce.output,
                ce.stderr,
            )
            err = f"""Error in command {ce.cmd}: 
            code: {ce.returncode}, stdout:
            {ce.output}
            stderr:
            {ce.stderr}
            """
            try:
                errfile = self.get_log_name(".err")
                if logoutput:
                    errfile = logoutput + ".err"
                elif logcmdline:
                    errfile = logcmdline + ".err"
                logger.error("Writing error output to %s", errfile)
                with open(errfile, "w") as fe:
                    fe.write(err)
            except:
                pass
            raise # This is to show the test as failed
        except TimeoutExpired as te:
            logger.warn("Timeout expired for command %s", te.cmd)
            ret = te.output

        if type(ret).__name__ == "bytes":
            ret = ret.decode("utf-8")
        logger.debug("Output: %s", ret)
        if logoutput:
            try:
                with open(logoutput, "a") as f:
                    f.write(ret)
            except Exception as e:
                logger.error("Could not write to file %s: %s", logoutput, e)
        return ret

    def start(self):
        """Start the module

        Raises:
            Exception: sth went wrong
        """
        logger.info(
            "\n"
            + "-" * 50
            + "\nStarting test %s against target %s with module %s"
            + "\n"
            + "-" * 50,
            self.testid,
            self.target,
            self.module_name,
        )
        if self.is_discovery():
            hostip = "discovery"
        else:
            if self.ip is None:
                raise Exception("Module should set IP Address")
            hostip = self.ip
        try:
            self.status = "started"
            self.get_host_obj(hostip).set_test_state(
                self.testid, self.status, self.module_name, self.target, self.args
            )
            self.run()
            self.status = "done"
        except Exception as e:
            logger.error(
                "Error in test %s against target %s: %s",
                self.testid,
                self.target,
                e,
                exc_info=True,
            )
            self.status = "error"
        finally:
            self.get_host_obj(hostip).set_test_state(self.testid, self.status)

        logger.info(
            "\n"
            + "-" * 50
            + "\ntest %s against target %s with module %s result: %s"
            + "\n"
            + "-" * 50,
            self.testid,
            self.target,
            self.module_name,
            self.status,
        )

    def is_discovery(self):
        return "discovery." in self.module_name

    def get_outdir(self, folder=None):
        global TEST_DATE_STR
        if self.is_discovery():
            h = ""
        else:
            h = self.target if self.target else ""  # For global modules

        if folder:
            outdir = os.path.join(TEST_WORKING_DIR, h, folder)
        else:
            outdir = os.path.join(TEST_WORKING_DIR, h)
        if not os.path.isdir(outdir):
            os.makedirs(outdir, exist_ok=True)
        return outdir

    def _get_flatten_args(self, argusekey):
        """strip bad chars and flatten args to make unique log file names

        Args:
            argusekey (list, optional): Will use the arg key instead of values for all keys in this list. Defaults to [].

        Returns:
            str: flattened args
        """
        args = []
        for k, v in self.args.items():
            if k in argusekey:
                v = k
            else:
                if isinstance(v, list):
                    v = "+".join(map(str, v))
                v = str(v)
                if os.path.isfile(v):
                    v = Path(v).stem
                v.replace(",", "+")
            args.append(re.sub(r"[^a-zA-Z0-9\.\+\-_]+", "", v))
        return "-".join(args)

    def get_log_name(self, ext="out", argusekey=[], folder=None):
        """Get log file name to output from a module

        Args:
            ext (str, optional): Extention. Defaults to "out".
            argusekey (list, optional): Will use the arg key instead of values for all keys in this list. Defaults to [].

        Returns:
            _type_: _description_
        """
        outdir = self.get_outdir(folder)

        args = self._get_flatten_args(argusekey)
        the_ext = ext
        if the_ext and not the_ext[0] == ".":
            the_ext = "." + the_ext
        filename = f"{self.__class__.__name__}_{args}{the_ext}".replace(
            "/", "-"
        ).replace(",", "-")
        return os.path.join(outdir, filename)

    @abstractmethod
    def run(self):
        pass
