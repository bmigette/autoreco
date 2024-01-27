from .logger import logger
from .state import statelock, TEST_STATE
from .config import DEFAULT_MAX_OUTPUT


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
    with statelock:
        for host, data in TEST_STATE.items():
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
