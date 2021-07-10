# -*- coding: utf-8 -*-
"""
**The pythonic way to deal with the McAfee SIEM API**

.. image:: https://avatars0.githubusercontent.com/u/50667087?s=200&v=4
        :target: https://mfesiem.github.io/docs/msiempy/msiempy.html
        :alt: Nitro
        :width: 50
        :height: 50

Welcome to the **msiempy** library documentation. 

:Note: 
    All public classes are imported into `msiempy` root package. 

    The classes listed below are the only public interfaces of the library - 
    together with `msiempy.core.utils` methods (generic utils, useful for custom querying).   
    
    Other modules and classes should not be used directly (they are mostly abstract anyway). 

:seealso: 
    - `Class diagram <classes.png>`_, (`Packages diagram <packages.png>`_)
    - `Samples folder <https://github.com/mfesiem/msiempy/tree/master/samples>`_
    - `Unittests <https://github.com/mfesiem/msiempy/tree/master/tests>`_
    - `msiem CLI <https://github.com/mfesiem/msiem>`_
    - `mfesiem.github.io <https://mfesiem.github.io>`_ (generated PDFs and other links)  

Back to `GitHub | README.md <https://github.com/mfesiem/msiempy>`_

"""        

from .__version__ import __version__ as VERSION

# Objects that where definied in the __init__.py package kept here cause people might depend on it. 
from .core.query import FilteredQueryList as deprecated_FilteredQueryList # Deprecated, Should not be used
from .core.types import NitroList as deprecated_NitroList # Deprecated, Should not be used
from ._deprecation import DeprecationHelper
_FilteredQueryList = DeprecationHelper(deprecated_FilteredQueryList, 
    "The usage of msiempy.FilteredQueryList is not supported, you can use EventManager to access contants defined in FilteredQueryList. This import will be removed in the future.")
FilteredQueryList = _FilteredQueryList
_NitroList = DeprecationHelper(deprecated_NitroList, 
    "The usage of msiempy.NitroList is not supported, please use a concrete manager class like EventManager, or use msiempy.core.types.NitroList directly. This import will be removed in the future.")
NitroList = _NitroList

# Objects part of the public API of the library
from .alarm import Alarm, AlarmManager
from .core.config import NitroConfig
from .core.session import NitroError, NitroSession
from .device import ESM, DataSource, DevTree
from .event import (Event, EventManager, FieldFilter, GroupedEvent,
                    GroupedEventManager, GroupFilter)
from .watchlist import Watchlist, WatchlistManager
__all__=[       "NitroConfig", "NitroError", "NitroSession", 
                "Alarm", "AlarmManager", "ESM", "DevTree", "DataSource", 
                "Event", "EventManager", "FieldFilter", "GroupFilter",
                "GroupedEvent", "GroupedEventManager", "Watchlist", "WatchlistManager" ]

