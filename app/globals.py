"""
Global State Management
"""
class Globals:
    def __init__(self):
        self.config = None
        self.state = None
        self.logger = None

_globals = Globals()

def set_globals(config=None, state=None, logger=None):
    if config is not None:
        _globals.config = config
    if state is not None:
        _globals.state = state
    if logger is not None:
        _globals.logger = logger

def get_config():
    return _globals.config

def get_state():
    return _globals.state

def get_logger():
    return _globals.logger