from .WorkThreader import WorkThreader
class runner(object):
    def __init__(self):
        WorkThreader.start_threads()