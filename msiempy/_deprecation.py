import logging
log = logging.getLogger("msiempy")

class DeprecationHelper(object):
    """
    Helper to deprecate a class. 
    Stolen https://stackoverflow.com/questions/9008444/how-to-warn-about-class-name-deprecation
    """
    def __init__(self, new_target, msg):
        self.new_target = new_target
        self.msg = msg

    def _warn(self):
        log.warning("Deprecated: %s"%self.msg)

    def __call__(self, *args, **kwargs):
        self._warn()
        return self.new_target(*args, **kwargs)

    def __getattr__(self, attr):
        self._warn()
        return getattr(self.new_target, attr)
