from .logger import logger
from .state import statelock, TEST_STATE

def print_summary():
    total_tests = 0
    total_hosts = 0
    success_tests = 0
    failed_tests = 0
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
                    else:
                        logger.warn("Test %s state: %s", testid, testdata["state"])

        logger.info("=" * 50)
        logger.info("# Ran %s Tests against %s hosts", total_tests, total_hosts)
        logger.info("# Success: %s, Failed: %s", success_tests, failed_tests)
        logger.info("=" * 50)