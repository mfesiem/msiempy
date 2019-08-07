![Logo](https://avatars0.githubusercontent.com/u/50667087?s=200&v=4 "Logo") 
### McAfee SIEM API Python wrapper
[![Build Status](https://travis-ci.org/mfesiem/msiempy.svg?branch=master)](https://travis-ci.org/mfesiem/msiempy)

This project aims to provide a basic API wrapper around the McAfee SIEM API to help make it more 
accessible and pythonic.

⚠️ This python module is currently experimental ⚠️

### Main features
- ESM monitoring (work in progress)
- Datasource management : add, edit, del - including client datasources (work in progress)
- Alarm management and querying : [asynchronous] filter, [un]acknowledge, delete (not working in v11.2.1 see #11).  
- Event querying : [asynchronous] dynamic query
- Watchlist operations : list all watchlists and add values (work in progress)
- Single stable session handler and built-in asynchronous jobs

### Documentation and links
- Python msiempy module documentation : https://mfesiem.github.io/docs/msiempy/index.html
- Class diagram : https://mfesiem.github.io/docs/msiempy/classes.png
- SIEM API documentation : https://ESM_HOSTNAME/rs/esm/help

### Installation 
```
pip install msiempy
```

### Configuration setup
The configuration file should be located securely in your path since it has credentials.
- For Windows:  %APPDATA%\.msiem\conf.ini
- For Mac :     $HOME/.msiem/conf.ini
- For Linux :   $XDG_CONFIG_HOME/.msiem/conf.ini or :   $HOME/.msiem/conf.ini
```
[esm]
host = ESM HOST NAME OR IP
user = USERNAME
passwd = PASSWORD IN BASE64, generate it like `echo 'p@ssw0d' | base 64`

[general]
verbose = yes
quiet = no
logfile = /var/log/msiempy/log.txt
timeout = 30
ssl_verify = no
output = text
```

You can initiate and configure the file with python cli.
```python
$ python3
>>> from msiempy import NitroConfig
>>> config=NitroConfig()
>>> config.iset('esm')
Enter [esm]host. Press <Enter> to keep empty: <type here>
Enter [esm]user. Press <Enter> to keep empty: <type here>
Enter [esm]passwd. Press <Enter> to skip: <type here>
>>> config.iset('general') [...]
>>> print(config)
Configuration file : /Users/username/.msiem/conf.ini
{'esm': {'host': '***', 'user': '***', 'passwd': '***=='}, 'general': {'verbose': 'no', 'quiet': 'False', 'logfile': '', 'timeout': '60', 'ssl_verify': 'no', 'output': 'text'}}
>>>config.write()
```

### Run tests
```
./setup.py test
[...]
----------------------------------------------------------------------
Ran 13 tests in 182.815s

OK
```
It souldn't take more than 5 minutes

### Example

#### Alarm
Print all unacknowledged alarms of the year. The number of alarms retreived is defined by the `page_size` property.
```python
import msiempy.alarm

alarms=msiempy.alarm.AlarmManager(
        time_range='CURRENT_YEAR',
        status_filter='unacknowledged',
        filters=[
                ('alarmName', 'IPS alarm'),
                ('ruleMessage','Wordpress')],
        page_zize='400')
        
alarms.load_data()
print(alarms)

alarms.load_events(extra_fields=['HostID','UserIDSrc'])
[ print alarm['events'] for alarm in alarms ]
```
See: https://mfesiem.github.io/docs/msiempy/alarm.html#msiempy.alarm.AlarmManager

#### Event
Query events according to filters, loading the data with comprensive parralel tasks and printing relevant data.
```python
import msiempy.event

events = msiempy.event.EventManager(
        time_range='LAST_3_DAYS',
        fields=['HostID', 'UserIDSrc'],
        filters=[
                msiempy.query.FieldFilter('DstIP', ['8.8.0.0/8',]),
                msiem.query.FieldFilter('HostID', ['mydomain.local'], operator='CONTAINS') ],
        limit=500,
        max_query_depth=2)
events.load_data(delta='2h', slots='4', workers=5)
print(events.get_text(fields=['Alert.LastTime','Alert.SrcIP', 'Alert.BIN(4', 'Alert.BIN(7)', 'Rule.msg']))
```
See: https://mfesiem.github.io/docs/msiempy/event.html#msiempy.event.EventManager

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
See: https://mfesiem.github.io/docs/msiempy/device.html#msiempy.device.ESM

#### Datasource
Load all datasources and search.  This is still work in progress.
```python
import msiempy.device

devtree = msiempy.device.DevTree()
```
See: https://mfesiem.github.io/docs/msiempy/device.html#msiempy.device.DevTree

### Contribute
If you like the project and think you could help with making it better, there are many ways you can do it:

Create new issue for new feature proposal or a bug
Implement existing issues
Help with improving the documentation
Spread a word about the project to your collegues, friends, blogs or any other channels
Any other things you could imagine
Any contribution would be of great help and I will highly appreciate it! If you have any questions, please create a new issue, or concact me via tris.la.tr@gmail.com

### Error report
Execute :
 ```cat ./.msiem/*.txt | cut -c 25-500 | grep -i error | sort | uniq```

### Disclaimer
This is an **UNOFFICIAL** project and is **NOT** sponsored or supported by **McAfee, Inc**. If you accidentally delete all of your datasources, don't call support (or me). Product access will always be limited to 'safe' methods and with respect to McAfee's intellectual property.
