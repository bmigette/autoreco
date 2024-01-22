import logging
FILE_LOGGING = True # Log all output to file by default
STDOUT_LOGGING = True # Log all output to stdout by default
NUM_THREADS = 8 # Number of threads
QUEUE_SIZE = 666 # Job queue size
QUEUE_WAIT_TIME = 10 # Time to wait for a queue item. This is time for graceful shutdown essentially
LOGLEVEL = logging.INFO