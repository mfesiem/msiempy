![Logo](https://avatars0.githubusercontent.com/u/50667087?s=200&v=4 "Logo") 

## McAfee SIEM API Python wrapper  

[![Tests](https://github.com/mfesiem/msiempy/workflows/test/badge.svg)](https://github.com/mfesiem/msiempy/actions)
[![Coverage](https://codecov.io/gh/mfesiem/msiempy/branch/master/graph/badge.svg)](https://codecov.io/gh/mfesiem/msiempy)
[![PyPI version](https://badge.fury.io/py/msiempy.svg)](https://badge.fury.io/py/msiempy)

This module aims to provide a basic API wrapper around the McAfee SIEM API to help make it more 
accessible and pythonic.

This python module is tested on windows, ubuntu and macos.   

### Main features
- ESM operations: monitor, show statuses  
- Datasource operations: add, edit, delete - including client datasources  
- Alarm operations and querying: filter, load pages, acknowledge, unacknowledge, delete, get triggering event, retreive from id  
- Event operations and querying: split queries, filter, add fields, set event's note, retreive from IPSIDAlertID  
- Watchlist operations : list, add, remove watchlists, add values, get values, retreive from id   
- Single stable session handler and built-in asynchronous jobs

### Known module implementations
- esm_healthmon : [Monitors ESM operations (CLI)](https://github.com/andywalden/esm_healthmon)
- msiem : [Query and manage ESM alarms (CLI)](https://github.com/tristanlatr/msiem)
- See [samples folder](https://github.com/mfesiem/msiempy/tree/master/samples) for other implementation examples and scripts !

### Documentation and links
- [Module documentation](https://mfesiem.github.io/docs/msiempy/index.html)
- [Class diagram](https://mfesiem.github.io/docs/msiempy/classes.png)
- McAfee SIEM API documentation : https://HOST/rs/esm/help

### Installation 
```
pip install msiempy
```
See [project on pypi.org](https://pypi.org/project/msiempy/)

### Authentication and configuration setup
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
verbose = yes
quiet = no
logfile = /var/log/msiempy/log.txt
timeout = 30
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
### Examples
See [examples.py](https://github.com/mfesiem/msiempy/tree/master/samples/examples.py) and all the [samples folder](https://github.com/mfesiem/msiempy/tree/master/samples) for more detailed uses !  
For further informations, please visit the [module documentation](https://mfesiem.github.io/docs/msiempy/index.html) ! :)  

#### Alarm
Print all `unacknowledged` alarms of the year who's name match `'IPS alarm'` and triggering event message match `'Wordpress'`. Then load the genuine `Event` objects (from the query module) that triggered the alarms and print all of their JSON representations.

The number of alarms retreived is defined by the `page_size` property.
```python
from msiempy.alarm import AlarmManager

alarms=AlarmManager(
        time_range='CURRENT_YEAR',
        status_filter='unacknowledged',
        filters=[
                ('alarmName', 'IPS alarm')],
        event_filters=[
                ('ruleMessage','Wordpress')],
        page_size=400)

alarms.load_data()
print(alarms.json)
```
See: [FilteredQueryList](https://mfesiem.github.io/docs/msiempy/index.html#msiempy.FilteredQueryList), [AlarmManager](https://mfesiem.github.io/docs/msiempy/alarm.html#msiempy.alarm.AlarmManager), [Alarm](https://mfesiem.github.io/docs/msiempy/alarm.html#msiempy.alarm.Alarm)

#### Event
Query events according to destination IP and hostname filters, load the data with comprensive parralel tasks working around the SIEM query `limit` and printing selected data fields. 
```python
from  msiempy.event import EventManager, FieldFilter

events = EventManager(
        time_range='LAST_3_DAYS',
        fields=['Alert.SrcIP', 'DSID'], # Alert.SrcIP is not queried by default # DSID is the event's datasource ID
        filters=[
                FieldFilter('DstIP', ['8.8.0.0/8',]),
                FieldFilter('HostID', ['mydomain.local'], operator='CONTAINS') ],
        limit=400)

events.load_data()
print(events.get_text(fields=['Alert.LastTime','Alert.SrcIP', 'Rule.msg']))
```
See: [FilteredQueryList](https://mfesiem.github.io/docs/msiempy/index.html#msiempy.FilteredQueryList), [EventManager](https://mfesiem.github.io/docs/msiempy/event.html#msiempy.event.EventManager), [FieldFilter](https://mfesiem.github.io/docs/msiempy/event.html#msiempy.event.FieldFilter), [Event](https://mfesiem.github.io/docs/msiempy/event.html#msiempy.event.Event)

`EventManager` `__init__()` can take other parameter like `order` or `max_query_depth`. `max_query_depth` parameter specify the number of sub-divisions the query can take at most (zero by default). The query is divided only if it hasn't completed with the current query settings.  

`load_data()` method accept also several parameters. It controls the query's division time range into slots of `delta` duration, then the query would be divided into the specified number of `slots`. Control also the number of asyncronous jobs using `workers` parameter. See  module documentation for more infos.  

See [filters](https://github.com/mfesiem/msiempy/blob/master/static/all_filters.json) list you can use to filter events.  
See [fields](https://github.com/mfesiem/msiempy/blob/master/static/all_fields.json) list you can request.

#### ESM
Print a few esm infos. This is still work in progress.
```python
>>> import msiempy.device

>>> esm=msiempy.device.ESM()
>>> esm.version()
'11.2.1'
>>> esm.recs()
[('ERC-1', 144116287587483648)]
>>> esm.buildstamp()
'11.2.1 20190725050014'
```
See: [ESM](https://mfesiem.github.io/docs/msiempy/device.html#msiempy.device.ESM)

#### Datasource
Load all datasources.  This is still work in progress.
```python
import msiempy.device

devtree = msiempy.device.DevTree()
```
See: [DevTree](https://mfesiem.github.io/docs/msiempy/device.html#msiempy.device.DevTree), [DataSource](https://mfesiem.github.io/docs/msiempy/device.html#msiempy.device.DataSource)

#### Watchlist
Print whatchlist list.  This is still work in progress.
```python
import msiempy.watchlist
watchlists=msiempy.watchlist.WatchlistManager()
print(watchlists)
```
See: [WatchlistManager](https://mfesiem.github.io/docs/msiempy/watchlist.html#msiempy.watchlist.WatchlistManager), [Watchlist](https://mfesiem.github.io/docs/msiempy/watchlist.html#msiempy.watchlist.Watchlist)

### Questions ?
If you have any questions, please create a new issue.

### Contribute
If you like the project and think you could help with making it better, there are many ways you can do it:
- Create new issue for new feature proposal or a bug
- Implement existing issues
- Help with improving the documentation
- Spread a word about the project to your collegues, friends, blogs or any other channels
- Any other things you could imagine
- Any contribution would be of great help and I will highly appreciate it! 

### Run tests
```
./setup.py test
```

### Error report
Configure log file reporting in the configuration file and execute :  
 ```cat /path/to/your/log/file | cut -c 25-500 | grep -i error | sort | uniq```

### Disclaimer
This is an **UNOFFICIAL** project and is **NOT** sponsored or supported by **McAfee, Inc**. If you accidentally delete all of your datasources, don't call support (or me). Product access will always be in respect to McAfee's intellectual property.
