import logging
log = logging.getLogger('msiempy')

from .base import Row, QueryManager
from .event import EventManager

class AlarmManager(QueryManager):
    """
    AlarmManager
    """
    pass

class Alarm(Row):
    """
    Alarm
    """
    @property
    def events(self):
        return EventManager()

    def acknowledge(self):
        pass

    def unacknowledge(self):
        pass

    def delete(self):
        pass

    def ceate_case(self):
        pass