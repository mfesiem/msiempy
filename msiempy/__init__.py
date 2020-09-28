# -*- coding: utf-8 -*-
"""
Welcome to the **msiempy** library documentation.  
The pythonic way to deal with McAfee SIEM API.  
Head out to one of the sub-modules to see objects definitions or scroll down for general documentation.  
Checkout the [msiem CLI](https://github.com/mfesiem/msiem) if you're looking for a CLI tool.  

***

Links : [GitHub](https://github.com/mfesiem/msiempy), [PyPI](https://pypi.org/project/msiempy/), [Class diagram](https://mfesiem.github.io/docs/msiempy/classes.png), [Packages diagram](https://mfesiem.github.io/docs/msiempy/packages.png), [SIEM API references Home](https://mfesiem.github.io) (generated PDFs and other links)  

***

## Installation 

```
python3 -m pip install msiempy
```

## Authentication and configuration setup  

The module offers a single point of authentication against your SIEM, so you don't have to worry about authentication when writting your scripts. This means that you need to preconfigure the authentication using the configuration file.

The configuration file is located (by default) securely in your user directory since it contains credentials.  
- For Windows:  `%APPDATA%\.msiem\conf.ini`  
- For Mac :     `$HOME/.msiem/conf.ini`  
- For Linux :   `$XDG_CONFIG_HOME/.msiem/conf.ini` or :   `$HOME/.msiem/conf.ini`  
```
[esm]
host = HOST
user = USER
passwd = PASSWORD's BASE64

[general]
verbose = no
quiet = no
logfile = /var/log/msiempy/log.txt
timeout = 60
ssl_verify = no
```

To set the password, you can use the [`msiempy_setup.py`](https://github.com/mfesiem/msiempy/blob/master/samples/msiempy_setup.py) script.  
You can also directly paste the password's base64 in the config file by doing:  
```python
>>> import base64
>>> passwd = 'P@assW0rd'
>>> print(base64.b64encode(passwd.encode('utf-8')).decode())
UEBhc3NXMHJk
```

## Examples

### Acknowledge alarms

See objects: `msiempy.alarm.AlarmManager` and `msiempy.alarm.Alarm`

Print all `unacknowledged` alarms of the year who's name *match* `'Test alarm'` and triggering event message match `'Wordpress'`.
Then acknowledge the alarms and make sure they are all acknowledged.  

The number of alarms retreived is defined by the `page_size` property.

```python
from msiempy import AlarmManager, Alarm
# Make an alarm query
alarms=AlarmManager(
        time_range='CURRENT_YEAR',
        status_filter='unacknowledged', # This filter is computed on the server side
        filters=[('alarmName', 'Test alarm')], # Other filters are applied as regex
        event_filters=[('ruleName','Wordpress')], 
        page_size=5 # Will only load 5 alarms (per query), increase limit to 500 or 1000 for better performance
    ) 
# Load the data into the list
alarms.load_data() 
# Print results
print("Alarm list: ")
print(alarms)
print(alarms.get_text(
        fields=['id','triggeredDate','acknowledgedDate', 'alarmName', 'acknowledgedUsername']))
# Acknowledge alarms
print("Acknowledge alarms...")
for alarm in alarms:
    alarm.acknowledge()
```  

### Execute an event query 

See objects: `msiempy.event.EventManager`, `msiempy.event.FieldFilter`, `msiempy.event.Event`  \

Query events according to destination IP and hostname filters, sorted by AlertID. 
```python
from  msiempy import EventManager, FieldFilter

print('Simple event query sorted by AlertID')
events = EventManager(
        time_range='CURRENT_YEAR',
        fields=['SrcIP', 'AlertID'], # SrcIP and AlertID are not queried by default
        filters=[
                FieldFilter('DstIP', ['0.0.0.0/0',]),
                FieldFilter('HostID', ['mail'], operator='CONTAINS')], # Please replace "mail" by a test hostname
        order=(('ASCENDING', 'AlertID')),
        limit=10) # Will only load 10 events (per query), increase limit to 500 or 1000 once finish testing for better performance

events.load_data()
print(events)
print(events.get_text(fields=['AlertID','LastTime','SrcIP', 'Rule.msg']))
```

### Add a note to events

Setting the note of an event, retreiving the genuine event from IPSIDAlertID and checking the note is well set. See [`add_wpsan_note.py`](https://github.com/mfesiem/msiempy/blob/master/samples/add_wpsan_note.py) script to see more how to add note to event that triggered alarms !  
```python
from  msiempy import EventManager, Event
events = EventManager(
        time_range='CURRENT_YEAR',
        limit=2
)
events.load_data()

for event in events :
        event.set_note("Test note")
        genuine_event = Event(id=event['IPSIDAlertID']) # Event data will be loaded with ipsGetAlertData
        assert "Test note" in genuine_event['note'], "The note doesn't seem to have been added to the event \n {}".format(event)
```

`msiempy.event.EventManager()` have other arguments: `order`, `start_time` and `end_time` or `time_rage`  

`msiempy.event.EventManager.load_data()` method accept also several parameters. It controls the query's division time range into slots of `delta` duration, then the query would be divided into the specified number of `slots`. Control also the number of asyncronous jobs using `workers` parameter. `max_query_depth` parameter specify the number of sub-divisions the query can take at most (zero by default). The query is divided only if it hasn't completed with the current query settings.   
See method documentation for more infos.  
 
See [`dump_all_fields.py`](https://github.com/mfesiem/msiempy/blob/master/samples/dump_all_fields.py) script to have full list of `fields` you can request and fields you can use with `FieldFilter` .

### Execute a grouped event query

Query the curent day events filtered by `IPSID` grouped by `ScrIP`.  

See objects: `msiempy.event.GroupedEventManager` and `msiempy.event.GroupedEvent`.  

```python
from msiempy import GroupedEventManager
import pandas
query = GroupedEventManager(
    time_range='LAST_3_DAYS', 
    field='SrcIP', 
    filters=[('IPSID', '144116287587483648')]) 
query.load_data()
# Sort the results by total count
results = list(reversed(sorted(query, key=lambda k: int(k['SUM(Alert.EventCount)']))))
# Display top 10 in a panda frame
frame=pandas.DataFrame(results[:10])
print(frame.to_string(index=False))
```

Tip: [`all_dev.py` script](https://github.com/mfesiem/msiempy/blob/master/samples/all_dev.py) can help you list all your datasources IDs (for the required `IPSID` filter).  

### Print ESM infos

See object: `msiempy.device.ESM`

Print a few esm infos. ESM object has not state for it self, it's a simple interface to data structures / values returned by the SIEM.  
```python
>>> from msiempy import ESM
>>> esm=ESM()
>>> esm.version()
'11.2.1'
>>> esm.recs()
[('ERC-1', 144116287587483648)]
>>> esm.buildstamp()
'11.2.1 20190725050014'
```

### Dump Datasources

See objects: `msiempy.device.DevTree`, `msiempy.device.DataSource`

Load all datasources and write all infos in a CSV file.  
```python
from msiempy import DevTree

devtree = DevTree()

with open('all-datasources.csv', 'w') as f:
        f.write(devtree.get_text(format='csv'))
```

### Dump Watchlists definitions

See objects: `msiempy.watchlist.WatchlistManager`, `msiempy.watchlist.Watchlist`

Print whatchlist list.
```python
from msiempy import WatchlistManager
watchlists=WatchlistManager()
print(watchlists)
```

### Use the Session object  

See object: `msiempy.core.session.NitroSession`  

You can choose not to use wrapper ojects like `AlarmManager` and use directly the Session object to make any API calls with any data. The Session object will handle intermittent SIEM errors.  

```python
from msiempy import NitroSession
s = NitroSession()
s.login()
# Get all last 24h alarms details with ESM API v2 (not supported by other objects yet)  
alarms = s.api_request('v2/alarmGetTriggeredAlarms?triggeredTimeRange=LAST_24_HOURS&status=&pageSize=500&pageNumber=1')
for a in alarms:
    a.update(s.api_request('v2/notifyGetTriggeredNotificationDetail', {'id':a['id']}))
```

### And more...

See the [samples folder](https://github.com/mfesiem/msiempy/tree/master/samples) for more detailed uses !  
You can also review the [tests](https://github.com/mfesiem/msiempy/tree/master/tests).   

## Changelog

Please refer to the [releases](https://github.com/mfesiem/msiempy/releases) github page.  

## Contribute

Pull requests are welcome!  
Please read the [contributing](https://github.com/mfesiem/msiempy/blob/master/CONTRIBUTING.md) file.  

## Run tests
Run all tests, sometimes the tests have to be reruns.  
```
pytest --reruns 3
```
You might also want to run per-file tests
```
pytest tests/auth/test_device.py
```
Or per-method test
````
python3 -m unittest tests.auth.test_event.T.test_add_note
````

## Code analysis

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/114821fcf6e14b8eb0f927e0112488c8)](https://www.codacy.com/gh/mfesiem/msiempy?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=mfesiem/msiempy&amp;utm_campaign=Badge_Grade) [![Maintainability](https://api.codeclimate.com/v1/badges/0cc21ba8f82394cb05f3/maintainability)](https://codeclimate.com/github/mfesiem/msiempy/maintainability)

## Error report
Configure log file reporting in the configuration file and and look for `"ERROR"`.  
Useful shell command to get simple list of errors:  
```
cat /path/to/your/log/file | grep -i error | sort | uniq
```

"""

# List all library objects that the user might need

from .core import NitroConfig, NitroError, NitroSession, FilteredQueryList, NitroList
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
