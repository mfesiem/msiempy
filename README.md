![Logo](https://avatars0.githubusercontent.com/u/50667087?s=200&v=4 "Logo") 
## McAfee SIEM API Python wrapper
[![Build Status](https://travis-ci.org/mfesiem/msiempy.svg?branch=master)](https://travis-ci.org/mfesiem/msiempy)

This project aims to provide a basic API wrapper around the McAfee SIEM API to help make it more 
accessible and pythonic.

 This python module is currently experimental 

### Main features
- ESM monitoring (work in progress)
- Datasource operations : add, edit, delete - including client datasources (work in progress)
- Alarm operations and querying : filter, [un]acknowledge, delete  
- Event querying and builtin workaround SIEM query `limit`
- Watchlist operations : list watchlists, add values (work in progress)
- Single stable session handler and built-in asynchronous jobs

### Documentation and links
- [Module documentation](https://mfesiem.github.io/docs/msiempy/index.html)
- [Class diagram](https://mfesiem.github.io/docs/msiempy/classes.png)
- McAfee SIEM API documentation : https://HOST/rs/esm/help

### Installation 
```
pip install msiempy
```

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
output = text
```

To set the password, you can edit the configuration dynamically with python. 
```python
>>> from msiempy import NitroConfig
>>> config=NitroConfig()
>>> config.iset('esm')
Enter [esm]host. Press <Enter> to keep empty: <type here>
Enter [esm]user. Press <Enter> to keep empty: <type here>
Enter [esm]passwd. Press <Enter> to skip: <type here>
>>> config.iset('general') [...]
>>> print(config)
Configuration file : /Users/username/.msiem/conf.ini
{'esm': {'host': '***', 'user': '***', 'passwd': '***=='}, 'general': {'verbose': 'no', 'quiet': 'no', 'logfile': '', 'timeout': '60', 'ssl_verify': 'no', 'output': 'text'}}
>>>config.write()
```

You can also directly paste the password's base64 in the config file by doing
```python
>>> import base64
>>> passwd = 'P@assW0rd'
>>> print(base64.b64encode(passwd.encode('utf-8')).decode())
UEBhc3NXMHJk
```
### Examples

#### Alarm
Print all `unacknowledged` alarms of the year who's name match `'IPS alarm'` and triggering event message match `'Wordpress'`. Then load the genuine `Event` objects (from the query module) that triggered the alarms and print all of their JSON representations.

The number of alarms retreived is defined by the `page_size` property.
```python
import msiempy.alarm

alarms=msiempy.alarm.AlarmManager(
        time_range='CURRENT_YEAR',
        status_filter='unacknowledged',
        filters=[
                ('alarmName', 'IPS alarm'),
                ('ruleMessage','Wordpress')],
        page_size='400')
        
alarms.load_data()
print(alarms)

alarms.load_events(extra_fields=['HostID','UserIDSrc'])
[ print alarm['events'].json for alarm in alarms ]
```
See: [FilteredQueryList](https://mfesiem.github.io/docs/msiempy/index.html#msiempy.FilteredQueryList), [AlarmManager](https://mfesiem.github.io/docs/msiempy/alarm.html#msiempy.alarm.AlarmManager), [Alarm](https://mfesiem.github.io/docs/msiempy/alarm.html#msiempy.alarm.Alarm)

#### Event
Query events according to destination IP and hostname filters, load the data with comprensive parralel tasks working around the SIEM query `limit` and printing selected data fields. 

The `max_query_depth` parameter specify the number of sub-divisions the query can take at most (zero by default). The query is divided only if it hasn't completed with the current query settings. The first division is done by dividing the query's time range into slots of `delta` duration, then the query would be divided into the specified number of `slots`. Control the number of asyncronous jobs using `workers` parameter.
```python
import msiempy.event

events = msiempy.event.EventManager(
        time_range='LAST_3_DAYS',
        fields=['HostID', 'UserIDSrc'],
        filters=[
                msiempy.event.FieldFilter('DstIP', ['8.8.0.0/8',]),
                msiem.event.FieldFilter('HostID', ['mydomain.local'], operator='CONTAINS') ],
        limit=500,
        max_query_depth=2)
events.load_data(delta='2h', slots='4', workers=5)

print(events.get_text(fields=['Alert.LastTime','Alert.SrcIP', 'Alert.BIN(4', 'Alert.BIN(7)', 'Rule.msg']))
```
See: [FilteredQueryList](https://mfesiem.github.io/docs/msiempy/index.html#msiempy.FilteredQueryList), [EventManager](https://mfesiem.github.io/docs/msiempy/event.html#msiempy.event.EventManager), [FieldFilter](https://mfesiem.github.io/docs/msiempy/event.html#msiempy.event.FieldFilter), [Event](https://mfesiem.github.io/docs/msiempy/event.html#msiempy.event.Event)

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

### Contribute
If you like the project and think you could help with making it better, there are many ways you can do it:

- Create new issue for new feature proposal or a bug
- Implement existing issues
- Help with improving the documentation
- Spread a word about the project to your collegues, friends, blogs or any other channels
- Any other things you could imagine
- Any contribution would be of great help and I will highly appreciate it! If you have any questions, please create a new issue.

### Run tests
```
./setup.py test
[...]
----------------------------------------------------------------------
Ran 13 tests in 182.815s

OK
```
It souldn't take more than 5 minutes

### Error report
Configure log file reporting in the configuration file and execute :  
 ```cat /path/to/your/log/file | cut -c 25-500 | grep -i error | sort | uniq```

### Disclaimer
This is an **UNOFFICIAL** project and is **NOT** sponsored or supported by **McAfee, Inc**. If you accidentally delete all of your datasources, don't call support (or me). Product access will always be limited to 'safe' methods and with respect to McAfee's intellectual property.
