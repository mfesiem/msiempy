# -*- coding: utf-8 -*-
"""
The core objects of the library.  

- `msiempy.core.session.NitroSession`  
- `msiempy.core.config.NitroConfig`

Abstract: 
- `msiempy.core.session.NitroS`, abstract query, list and dict.    
"""


from .types import NitroList, NitroDict, NitroObject
from .query import FilteredQueryList
from .session import NitroSession, NitroError
from .config import NitroConfig