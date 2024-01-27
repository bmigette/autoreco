class TestJob():
    """A simple wrapper for queue job, because we need to override comparison for queue items
    """
    def __init__(self, priority, data):
        self.priority = int(priority)
        self.data = data
        
    def __lt__(self, other):
        if self.priority == other.priority:
            return True
        return self.priority < other.priority
    
    def __repr__(self):
        return str(self.data)