import abc
import collections

from .session import NitroSession

class NitroError(Exception):
    """
    Base internal exception
    """
    pass

class NitroBase(abc.ABC):
    """
    Base class for all nitro objects. All objects have a reference t the single NitroSession object that handle the esm requests
    """

    def __init__(self):
        """
        self.nitro.request('esm-get-times')
        """
        self.nitro=NitroSession()

    def text(self) -> str:
        pass

    def json(self) -> dict:
        pass


class Row(NitroBase, collections.UserDict):
    """
    Base class that represent any SIEM data that can be represented as a row of a manager. Exemple : Event, Alarm, etc...
    Inherits from dict
    """
    def __init__(self):
        self.is_selected=False

    def select(self):
        pass

    def unselect(self):
        pass

class Manager(NitroBase, collections.UserList):
    """
    Base class for Managers objects. 
    Inherits from list
    """

    def __init__(self):
        pass

    def select(self, range, regex, invert):
        pass

    def unselect(self, range, regex, invert):
        pass

    def search(self, regex) -> list:
        pass

    def clear(self):
        pass

    def perform(self, callable, on, confirm, *args, **kwargs):
        pass

class QueryManager(Manager):
    """
    Base class for query based managers. QueryManager object can handle time_ranges.
    """
    def execute(self):
        pass

    def filters(self, *filters):
        pass

    def add_filter(self, filter):
        pass

    def clear_filters(self):
        pass

    