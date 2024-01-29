from .logger import logger
from .State import State
from .config import DEFAULT_MAX_OUTPUT
import re

def max_output(thestr:str , max = DEFAULT_MAX_OUTPUT):
    if not isinstance(thestr, str):
        return thestr
    if len(thestr) > max:
        return thestr[:max] +"\ ---- output omitted ----"
    else:
        return thestr

def print_summary():
    total_tests = 0
    total_hosts = 0
    success_tests = 0
    failed_tests = 0
    started_tests = 0
    for host, data in State().TEST_STATE.items():
        total_hosts += 1
        if "tests_state" in data:
            for testid, testdata in data["tests_state"].items():
                total_tests += 1
                if testdata["state"] == "done":
                    success_tests += 1
                elif testdata["state"] == "error":
                    failed_tests += 1
                elif testdata["state"] == "started":
                    started_tests += 1
                else:
                    pass
                    # logger.warn("Test %s state: %s", testid, testdata["state"])
        from .WorkThreader import WorkThreader

        logger.info("=" * 50)
        logger.info(
            "# Running / Ran %s Tests against %s hosts", total_tests, total_hosts
        )
        logger.info(
            "# Success: %s, Failed: %s, Running: %s, Queued: %s",
            success_tests,
            failed_tests,
            started_tests,
            WorkThreader.queue.qsize(),
        )
        logger.info("=" * 50)


def is_ip(ip: str):
    """Check if a string is an IP

    Args:
        ip (str): IP Address

    Returns:
        bool: yes or no
    """
    match = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", ip)
    return bool(match)

def is_ip_state_subnets(ip: str):
    """Checks if an IP is in same subnets that hosts in state to avoid scanning the internet :D

    Args:
        ip (str): The IP ADdress
    """
    # Yes, this could be improved
    subnets = []
    state = State().TEST_STATE.copy()
    for k, v in state.items():
        if k == "discovery":
            continue
        ip_parts = k.split(".")
        ip_parts[-1] = "0"
        subnet = ".".join(ip_parts)
        if subnet not in subnets:
            subnets.append(subnet)
    logger.debug("Known subnets: %s", subnets)
    ip_parts = ip.split(".")
    ip_parts[-1] = "0"
    subnet = ".".join(ip_parts)
    return subnet in subnets