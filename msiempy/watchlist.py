import logging
log = logging.getLogger('msiempy')

from .base import Item, Manager
class WatchlistManager(Manager):
    pass

class Watchlist(Item):
    def add_element(self, element):
        pass
