import logging
log = logging.getLogger('msiempy')

from .base import Row, Manager
class WatchlistManager(Manager):
    pass

class Watchlist(Row):
    def add_element(self, element):
        pass
