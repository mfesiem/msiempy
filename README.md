![Logo](https://avatars0.githubusercontent.com/u/50667087?s=200&v=4 "Logo") 

## McAfee SIEM API Python wrapper  

[![Tests](https://github.com/mfesiem/msiempy/workflows/test/badge.svg)](https://github.com/mfesiem/msiempy/actions)
[![Coverage](https://codecov.io/gh/mfesiem/msiempy/branch/master/graph/badge.svg)](https://codecov.io/gh/mfesiem/msiempy)
[![PyPI version](https://badge.fury.io/py/msiempy.svg)](https://pypi.org/project/msiempy/)
[![Docs](https://img.shields.io/badge/-documentation-blue)](https://mfesiem.github.io/docs/msiempy/index.html)

This module aims to provide a simple API wrapper around the McAfee SIEM API principal components.  
Code design is accessible and pythonic via list-like and dict-like objects interfaces.    

### Main features
- ESM operations: monitor, show statuses  
- Datasource operations: add, edit, delete - including client datasources, retreive from ID     
- Alarm operations and querying: filter, load pages, acknowledge, unacknowledge, delete, get triggering event, retreive from ID  
- Event operations and querying: group queries, filter, add fields, set event's note, retreive from ID   
- Watchlist operations : list, add/remove watchlists, add/remove values, get values, retreive from ID  
- Single stable session handler  

#### Known module implementations
- msiem CLI : [CLI tools for ESM](https://github.com/mfesiem/msiem)
- esm_healthmon : [Monitors ESM operations](https://github.com/andywalden/esm_healthmon)
- track-host: [Rapidly request event logs to track a workstation](https://github.com/mfesiem/track-host) 
- See [samples folder](https://github.com/mfesiem/msiempy/tree/master/samples) for other implementation examples and scripts !

### Installation 
```
python3 -m pip install msiempy
```

### **Read the [module documentation](https://mfesiem.github.io/docs/msiempy/index.html)**  

### Disclaimer
This is an **UNOFFICIAL** project and is **NOT** sponsored or supported by **McAfee, Inc**. If you accidentally delete all of your datasources, don't call support (or us). Product access will always be in respect to McAfee's intellectual property.
