from ..ModuleInterface import ModuleInterface
from ...logger import logger


class WKHtmlToImage(ModuleInterface):
    """Class to run wkhtmltoimage against a single host"""
    def run(self):
        self.web = True
        logfile = self.get_log_name("log")
        cmdfile =  self.get_log_name("cmd")
        pngfile =  self.get_log_name("png")
        url = self.args["url"]
        host = ""
        if "host" in self.args and self.args["host"]:
            host = "--custom-header-propagation --custom-header Host " + self.args["host"]
        self.command = f"wkhtmltoimage --format png {host} {url} {pngfile}"
        logger.debug("Starting wkhtmltoimage with command %s", self.command)
        self.output = self.get_system_cmd_outptut(self.command, logcmdline=cmdfile, logoutput=logfile)
        self.check_file_empty_and_move(logfile)

   