import logging
log = logging.getLogger('msiempy')

from .base import Row, QueryManager

class EventManager(QueryManager):
    """
    EventManage
    """ 
    pass

class Event(Row):
    """
    Event
    """
    def clear_notes(self):
        pass

    def add_note(self, note):
        pass