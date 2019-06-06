import logging
log = logging.getLogger('msiempy')

from .base import Item, QueryManager

class EventManager(QueryManager):
    """
    EventManage
    """ 
    pass

class Event(Item):
    """
    Event
    """
    def clear_notes(self):
        pass

    def add_note(self, note):
        pass