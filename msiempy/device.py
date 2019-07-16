"""Module offering ESM, ERC, DevTree and DataSource management (TODO)
"""

import logging
log = logging.getLogger('msiempy')

from . import NitroObject, Item, Manager

class Device(NitroObject):
    pass

class EntrepriseSecurityManager(Device):
    pass

class EventReceiver(Device):
    pass

class DataSource(Item):
    pass

class DevTree(Manager):
    pass