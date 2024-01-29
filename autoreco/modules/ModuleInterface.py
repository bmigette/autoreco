from abc import ABC, abstractmethod
import os
from subprocess import STDOUT, check_output, CalledProcessError, TimeoutExpired, Popen, PIPE
import shlex
import re
from pathlib import Path
from threading import Timer
import time

from ..logger import logger
from ..State import State
from ..config import DEFAULT_PROCESS_TIMEOUT, DEFAULT_IDLE_TIMEOUT
from ..utils import max_output, is_ip
from ..TestHost import TestHost



class ModuleInterface(ABC):
    """Generic modules functions"""

    def __init__(self, testid, target, module_name, args={}):
        self.status = "notstarted"
        self.args = args
        self.testid = testid
        self.target = target
        self.module_name = module_name
        self.progress = ""
        if is_ip(target):
            self.ip = target
        else:
            self.ip = None

    def get_host_obj(self, ip: str) -> TestHost:
        return TestHost(ip)

    def _run_cmd_stream(self, cmd, timeout_sec, callback):
        # We mix stderr and stdout, because some processes like gobuster shows progress in stderr, and stdout will be silent
        proc = Popen(cmd, stdout=PIPE, stderr=STDOUT, bufsize=1,
                     text=True, universal_newlines=True)
        buffer = []
        while proc.poll() is None:
            try:
                timer = Timer(timeout_sec, proc.kill)
                timer.start()
                output = proc.stdout.readline()
                try:
                    progress = callback(output)
                    buffer.append(output)
                    if progress:
                        self.progress = progress
                except Exception as ie:
                    logger.error("Error in callback: %s", ie, exc_info=True)
                finally:
                    timer.cancel()
                
            except Exception as e:
                proc.kill()
                logger("_run_stream error with command %s: %s", cmd, e)
                #outs, errs = proc.communicate()
                #raise TimeoutError(f"stdout: {outs}\nstderr: {errs}")
        if proc.returncode != 0:
            raise CalledProcessError(proc.returncode, cmd, "\n".join(buffer))
        return "\n".join(buffer)

    def get_system_cmd_outptut(
        self,
        command: str,
        timeout: int = DEFAULT_PROCESS_TIMEOUT,
        logoutput=None,
        logcmdline=None,
        realtime=False,
        idletimeout: int = DEFAULT_IDLE_TIMEOUT,
        progresscb = None
    ):
        """Run a system command and get the output

        Args:
            command (str): command line
            timeout (int, optional): Process timeout. Defaults to DEFAULT_PROCESS_TIMEOUT.
            logoutput (_type_, optional): _description_. Defaults to None.
            logcmdline (str, optional): Filename to write cmd to. Defaults to None.
            realtime (bool, optional): Use stream to read stdout realtime. Defaults to False.
            idletimeout (int, optional): Consider process stuck if no out after this time. Defaults to DEFAULT_IDLE_TIMEOUT.
            progresscb (function, optional): Callback to parse progress if realtime is True. Defaults to None.

        Returns:
            str: command output
        """

        if logcmdline:
            try:
                with open(logcmdline, "a") as f:
                    f.write(command)
            except Exception as e:
                logger.error(
                    "Could not write cmd to file %s: %s", logcmdline, e)
        if not isinstance(command, list):
            command = shlex.split(command)
        logger.debug("Executing command %s in module %s...",
                     command, self.module_name)
        try:
            if realtime:
                ret = self._run_cmd_stream(command, idletimeout, progresscb)
            else:
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
                max_output(ce.output),
                max_output(ce.stderr),
            )
            err = f"Error in command {ce.cmd}: \n"
            err = err + f"code: {ce.returncode}, stdout:\n"
            err = err + f"{ce.output}\n"
            err = err + "stderr:\n"
            err = err + f"{ce.stderr}"
            
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
            raise  # This is to show the test as failed
        except TimeoutExpired as te:
            logger.warn("Timeout expired for command %s", te.cmd)
            ret = f"{te.stdout=} \n{te.stderr=}"
            self.status = "error"
        except TimeoutError as te2:
            logger.warn(
                "Timeout expired for Stream command %s: %s", command, te2)
            ret = ""
            self.status = "error"

        if type(ret).__name__ == "bytes":
            ret = ret.decode("utf-8")
        logger.debug("Output: %s", max_output(ret))
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

    def is_userenum(self):
        return "userenum." in self.module_name

    def get_outdir(self, folder=None):
        """Get log out folder

        Args:
            folder (str, optional): Extra folder. Defaults to None.

        Returns:
            str: folder path
        """
        if self.is_discovery():
            h = ""
        else:
            h = self.target if self.target else ""  # For global modules

        basedir = State().TEST_WORKING_DIR
        if self.is_userenum():
            basedir = os.path.join(basedir, "userenum")
        if folder:
            outdir = os.path.join(basedir, h, folder)
        else:
            outdir = os.path.join(basedir, h)

        if not os.path.isdir(outdir):
            os.makedirs(outdir, exist_ok=True)
        return outdir

    def _get_flatten_args(self, argusekey = [], ignorekeys = ["password", "pass"]):
        """strip bad chars and flatten args to make unique log file names

        Args:
            argusekey (list, optional): Will use the arg key instead of values for all keys in this list. Defaults to [].
            ignorekeys (list, optional): Ignore all keys in this list. Defaults to [].

        Returns:
            str: flattened args
        """
        args = []
        for k, v in self.args.items():
            if k.lower() in [x.lower() for x in ignorekeys]:
                continue
            if k in argusekey:
                v = k+str(len(v))
            else:
                if isinstance(v, list):
                    v = "+".join(map(str, v))
                v = str(v)
                if os.path.isfile(v):
                    v = Path(v).stem
                v.replace(",", "+")
            args.append(re.sub(r"[^a-zA-Z0-9\.\+\-_]+", "_", v))
        return "-".join(args)

    def get_log_name(self, ext="out", argusekey=[], folder=None, ignorekeys = ["password", "pass"]):
        """Get log file name to output from a module

        Args:
            ext (str, optional): Extention. Defaults to "out".
            argusekey (list, optional): Will use the arg key instead of values for all keys in this list. Defaults to [].
            ignorekeys (list, optional): Ignore all keys in this list. Defaults to [].

        Returns:
            _type_: _description_
        """
        outdir = self.get_outdir(folder)

        args = self._get_flatten_args(argusekey, ignorekeys)
        if args:
            args = f"_{args}"
        the_ext = ext
        if the_ext and not the_ext[0] == ".":
            the_ext = "." + the_ext
        filename = f"{self.__class__.__name__}{args}{the_ext}".replace(
            "/", "-"
        ).replace(",", "-")
        return os.path.join(outdir, filename)

    @abstractmethod
    def run(self):
        pass
