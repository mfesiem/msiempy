# -*- coding: utf-8 -*-
"""
**The pythonic way to deal with the McAfee SIEM API**

.. image:: https://avatars0.githubusercontent.com/u/50667087?s=200&v=4
        :target: https://mfesiem.github.io/docs/msiempy/msiempy.html
        :alt: Nitro
        :width: 50
        :height: 50

Welcome to the **msiempy** library documentation. 

Back to `GitHub | README.md <https://github.com/mfesiem/msiempy>`_

"""        

# List part of the library objects (not all are public)
from .core.config import NitroConfig
from .core.session import NitroError, NitroSession
from .core.types import NitroList
from .core.query import FilteredQueryList
from .alarm import Alarm, AlarmManager
from .device import ESM, DevTree, DataSource
from .event import (
    Event,
    EventManager,
    GroupFilter,
    FieldFilter,
    GroupedEventManager,
    GroupedEvent,
)
from .watchlist import Watchlist, WatchlistManager
from .__version__ import __version__ as VERSION

# Objects part of the public API of the library
__all__=[       "NitroConfig", "NitroError", "NitroSession", 
                "Alarm", "AlarmManager", "ESM", "DevTree", "DataSource", 
                "Event", "EventManager", "FieldFilter", "GroupFilter",
                "GroupedEvent", "GroupedEventManager", "Watchlist", "WatchlistManager" ]