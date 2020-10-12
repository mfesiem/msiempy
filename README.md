![Logo](https://avatars0.githubusercontent.com/u/50667087?s=200&v=4 "Logo") 

## McAfee SIEM API Python wrapper  


<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="166.5" height="20"><linearGradient id="smooth" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="round"><rect width="166.5" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#round)"><rect width="65.5" height="20" fill="#555"/><rect x="65.5" width="101.0" height="20" fill="#007ec6"/><rect width="166.5" height="20" fill="url(#smooth)"/></g><g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110"><image x="5" y="3" width="14" height="14" xlink:href="https://dev.w3.org/SVG/tools/svgweb/samples/svg-files/python.svg"/><text x="422.5" y="150" fill="#010101" fill-opacity=".3" transform="scale(0.1)" textLength="385.0" lengthAdjust="spacing">python</text><text x="422.5" y="140" transform="scale(0.1)" textLength="385.0" lengthAdjust="spacing">python</text><text x="1150.0" y="150" fill="#010101" fill-opacity=".3" transform="scale(0.1)" textLength="910.0" lengthAdjust="spacing">3.6, 3.7, 3.8, 3.9</text><text x="1150.0" y="140" transform="scale(0.1)" textLength="910.0" lengthAdjust="spacing">3.6, 3.7, 3.8, 3.9</text></g></svg>
[![Tests](https://github.com/mfesiem/msiempy/workflows/test-and-publish/badge.svg)](https://github.com/mfesiem/msiempy/actions)
[![Coverage](https://codecov.io/gh/mfesiem/msiempy/branch/master/graph/badge.svg)](https://codecov.io/gh/mfesiem/msiempy)
[![PyPI version](https://badge.fury.io/py/msiempy.svg)](https://pypi.org/project/msiempy)
[![Docs](https://img.shields.io/badge/-documentation-blue)](https://mfesiem.github.io/docs/msiempy/msiempy.html)

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

### **Read the [library documentation](https://mfesiem.github.io/docs/msiempy/msiempy.html)**  

### Disclaimer
This is an **UNOFFICIAL** project and is **NOT** sponsored or supported by **McAfee, Inc**. If you accidentally delete all of your datasources, don't call support (or us). Product access will always be in respect to McAfee's intellectual property.
