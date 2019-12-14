![Logo](https://avatars0.githubusercontent.com/u/50667087?s=200&v=4 "Logo") 

## McAfee SIEM API Python wrapper  

[![Tests](https://github.com/mfesiem/msiempy/workflows/test/badge.svg)](https://github.com/mfesiem/msiempy/actions)
[![Coverage](https://codecov.io/gh/mfesiem/msiempy/branch/master/graph/badge.svg)](https://codecov.io/gh/mfesiem/msiempy)
[![PyPI version](https://badge.fury.io/py/msiempy.svg)](https://pypi.org/project/msiempy/)

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
##### Stable
```
pip install msiempy
```
See [project on pypi.org](https://pypi.org/project/msiempy/)

##### Development
```
git clone https://github.com/mfesiem/msiempy.git
cd msiempy && python3 ./setup.py install
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
### Examples
See [`examples.py`](https://github.com/mfesiem/msiempy/tree/master/samples/examples.py) and all the [samples folder](https://github.com/mfesiem/msiempy/tree/master/samples) for more detailed uses !  
For further informations, please visit the [module documentation](https://mfesiem.github.io/docs/msiempy/index.html) ! :)  

#### Alarm
Print all `unacknowledged` alarms of the year who's name match `'IPS alarm'` and triggering event message match `'Wordpress'`. Then print all of their JSON representations.

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
print(alarms)
print(alarms.json)
```


Print, acknowledge and unackowledge some alarms based on filters.  
```python
from msiempy.alarm import AlarmManager, Alarm

alarms=AlarmManager(
        time_range='CURRENT_YEAR',
        status_filter='unacknowledged',
        filters=[('alarmName', 'Test alarm')],
        event_filters=[('ruleName','Postfix')], 
        page_size=5)

print("Alarm list before load_data: ")
print(alarms)
print(alarms.json)

alarms.load_data()

print("Alarm list: ")
print(alarms)
print(alarms.get_text(
        fields=['id','triggeredDate','acknowledgedDate', 'alarmName', 'acknowledgedUsername']))

print("Acknowledge alarms...")

[ alarm.acknowledge() for alarm in alarms ]
while any( [ alarm['acknowledgedDate'] in ['', None] for alarm in alarms ] ): 
        time.sleep(1)
        [ alarm.refresh() for alarm in alarms ]
print(alarms.get_text(
        fields=['id','triggeredDate','acknowledgedDate', 'alarmName', 'acknowledgedUsername']))

print("Unacknowledge alarms...")
[ alarm.unacknowledge() for alarm in alarms ]
while any( [ alarm['acknowledgedDate'] not in ['', None] for alarm in alarms ] ): 
        time.sleep(1)
        [ alarm.refresh() for alarm in alarms ]
print(alarms.get_text(
        fields=['id','triggeredDate','acknowledgedDate', 'alarmName', 'acknowledgedUsername']))
```  

<details><summary>Output</summary>
<p>
        
        Alarm list before load_data: 
        <super: <class 'NitroList'>, <AlarmManager object>> containing 0 elements ; keys=set()
        []
        INFO - Login into ESM 207.179.200.58:4443 with username NGCP. Last login 12/12/2019 18:04:48
        INFO - Getting alarms infos...
        INFO - Getting events infos...
        INFO - The alarm Test Alarm (12/12/2019 18:05:26) has no events associated
        INFO - 4 alarms are matching your filter(s)
        Alarm list: 
        <super: <class 'NitroList'>, <AlarmManager object>> containing 4 elements ; keys={'alretRateMin', 'filters', 'NE', 'severity', 'XMIN', 'matchField', 'description', 'queryId', 'escalatedDate', 'alertRateCount', 'percentAbove', 'NID', 'offsetMinutes', 'acknowledgedDate', 'triggeredDate', 'percentBelow', 'EC', 'CTYPE', 'assignee', 'assigneeId', 'caseName', 'summary', 'DCHNG', 'caseId', 'id', 'alarmName', 'matchValue', 'actions', 'iocName', 'conditionType', 'iocId', 'acknowledgedUsername', 'useWatchlist', 'maximumConditionTriggerFrequency', 'events'}
        |        id       |    triggeredDate    | acknowledgedDate | alarmName  | acknowledgedUsername |
        | {'value': 3840} | 12/12/2019 17:54:46 |       None       | Test Alarm |                      |
        | {'value': 3839} | 12/12/2019 17:42:56 |       None       | Test Alarm |                      |
        | {'value': 3838} | 12/12/2019 17:29:16 |       None       | Test Alarm |                      |
        | {'value': 3837} | 12/12/2019 17:11:56 |       None       | Test Alarm |                      |
        Acknowledge alarms...
        |        id       |    triggeredDate    |   acknowledgedDate  | alarmName  | acknowledgedUsername |
        | {'value': 3840} | 12/12/2019 17:54:46 | 12/12/2019 18:07:53 | Test Alarm |                      |
        | {'value': 3839} | 12/12/2019 17:42:56 | 12/12/2019 18:07:53 | Test Alarm |                      |
        | {'value': 3838} | 12/12/2019 17:29:16 | 12/12/2019 18:07:53 | Test Alarm |                      |
        | {'value': 3837} | 12/12/2019 17:11:56 | 12/12/2019 18:07:53 | Test Alarm |                      |
        Unacknowledge alarms...
        |        id       |    triggeredDate    | acknowledgedDate | alarmName  | acknowledgedUsername |
        | {'value': 3840} | 12/12/2019 17:54:46 |       None       | Test Alarm |                      |
        | {'value': 3839} | 12/12/2019 17:42:56 |       None       | Test Alarm |                      |
        | {'value': 3838} | 12/12/2019 17:29:16 |       None       | Test Alarm |                      |
        | {'value': 3837} | 12/12/2019 17:11:56 |       None       | Test Alarm |                      |
        
</p>
</details>


The number of alarms retreived is defined by the `page_size` property.

See: [FilteredQueryList](https://mfesiem.github.io/docs/msiempy/index.html#msiempy.FilteredQueryList), [AlarmManager](https://mfesiem.github.io/docs/msiempy/alarm.html#msiempy.alarm.AlarmManager), [Alarm](https://mfesiem.github.io/docs/msiempy/alarm.html#msiempy.alarm.Alarm)

#### Event
Query events according to destination IP and hostname filters, sorted by AlertID. 
```python
from  msiempy.event import EventManager, FieldFilter

print('Simple event query sorted by AlertID')
events = EventManager(
        time_range='CURRENT_YEAR',
        fields=['SrcIP', 'AlertID'], # SrcIP and AlertID are not queried by default
        filters=[
                FieldFilter('DstIP', ['0.0.0.0/0',]),
                FieldFilter('HostID', ['mail'], operator='CONTAINS')], # Please replace "mail" by a test hostname
        order=(('ASCENDING', 'AlertID')),
        limit=10)

events.load_data()
print(events)
print(events.get_text(fields=['AlertID','LastTime','SrcIP', 'Rule.msg']))
```

<details><summary>Output</summary>
<p>

        Simple event query sorted by AlertID
        INFO - Login into ESM 207.179.200.58:4443 with username NGCP. Last login 12/12/2019 18:18:12
        WARNING - The query is not complete... Try to divide in more slots or increase the limit
        <super: <class 'NitroList'>, <EventManager object>> containing 10 elements ; keys={'Alert.AlertID', 'Alert.SrcIP', 'Rule.msg', 'Alert.LastTime', 'Alert.IPSIDAlertID'}
        | AlertID |       LastTime      |     SrcIP      |                      Rule.msg                      |
        |  139345 | 12/09/2019 18:22:21 |   22.22.24.4   |      Postfix Message moved to incoming queue       |
        |  139346 | 12/09/2019 18:22:21 |   22.22.24.4   | Postfix Message moved to active queue for delivery |
        |  139351 | 12/09/2019 18:22:21 |   22.22.24.4   |                Postfix Message sent                |
        |  139352 | 12/09/2019 18:22:21 |   22.22.24.4   |          Linux Postfix qmgr mail removed           |
        |  139367 | 12/09/2019 18:19:09 |   22.22.24.4   |       Postfix Max connection rate statistics       |
        |  139368 | 12/09/2019 18:19:09 |   22.22.24.4   |      Postfix Max connection count statistics       |
        |  139369 | 12/09/2019 18:19:09 |   22.22.24.4   |         Postfix Max cache size statistics          |
        |  139370 | 12/09/2019 18:20:16 | 209.85.160.178 |             Postfix Connect from host              |
        |  139371 | 12/09/2019 18:20:17 | 209.85.160.178 |          Postfix Client message transfer           |
        |  139372 | 12/09/2019 18:20:17 | 209.85.160.178 |            Postfix Disconnect from host            |


</p>
</details>

Setting the note of an event, retreiving the genuine event from IPSIDAlertID and checking the note is well set. See [`add_wpsan_note.py`](https://github.com/mfesiem/msiempy/blob/master/samples/add_wpsan_note.py) script to see more how to add note to event that triggered alarms !  
```python
events = msiempy.event.EventManager(
        time_range='CURRENT_YEAR',
        limit=2
)
events.load_data()

for event in events :
        event.set_note("Test note")
        genuine_event = msiempy.event.Event(id=event['IPSIDAlertID'])
        assert "Test note" in genuine_event['note'], "The note doesn't seem to have been added to the event \n {}".format(event)
```


See: [FilteredQueryList](https://mfesiem.github.io/docs/msiempy/index.html#msiempy.FilteredQueryList), [EventManager](https://mfesiem.github.io/docs/msiempy/event.html#msiempy.event.EventManager), [FieldFilter](https://mfesiem.github.io/docs/msiempy/event.html#msiempy.event.FieldFilter), [Event](https://mfesiem.github.io/docs/msiempy/event.html#msiempy.event.Event)

`EventManager` `__init__()` can take other parameter like `order` or `start_tinme` and `end_time` if `time_rage` is `CUSTOM`.  

`EventManager` `load_data()` method accept also several parameters. It controls the query's division time range into slots of `delta` duration, then the query would be divided into the specified number of `slots`. Control also the number of asyncronous jobs using `workers` parameter. `max_query_depth` parameter specify the number of sub-divisions the query can take at most (zero by default). The query is divided only if it hasn't completed with the current query settings.   
See  module documentation for more infos.  
 
See [`dump_all_fields.py`](https://github.com/mfesiem/msiempy/blob/master/samples/dump_all_fields.py) script to have full list of `fields` you can request and fields you can use with `FieldFilter` .

#### ESM
Print a few esm infos. ESM object has not state for it self, it's a simple interface to data structures / values returned by the SIEM.  
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
Load all datasources. 
```python
import msiempy.device

devtree = msiempy.device.DevTree()
```
See: [DevTree](https://mfesiem.github.io/docs/msiempy/device.html#msiempy.device.DevTree), [DataSource](https://mfesiem.github.io/docs/msiempy/device.html#msiempy.device.DataSource)

#### Watchlist
Print whatchlist list.
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
Run all tests
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


### Error report
Configure log file reporting in the configuration file and execute :  
 ```cat /path/to/your/log/file | grep -i error | sort | uniq```

### Disclaimer
This is an **UNOFFICIAL** project and is **NOT** sponsored or supported by **McAfee, Inc**. If you accidentally delete all of your datasources, don't call support (or me). Product access will always be in respect to McAfee's intellectual property.
