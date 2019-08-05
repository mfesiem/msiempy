### McAfee SIEM API Python wrapper
[![Build Status](https://travis-ci.org/mfesiem/msiempy.svg?branch=master)](https://travis-ci.org/mfesiem/msiempy)

This project aims to provide a basic API wrapper around the McAfee SIEM API to help make it more 
accessible and pythonic.

### Documentation and links
- msiempy API technical documentation : https://mfesiem.github.io/docs/msiempy/index.html
- Class diagram : https://mfesiem.github.io/docs/msiempy/classes.png
- SIEM API technical documentation : https://[ESM HOST NAME OR IP]/rs/esm/help

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
host = [ESM HOST NAME OR IP]
user = [USERNAME]
passwd = [PASSWORD IN BASE64]

[general]
verbose = yes
quiet = no
logfile = /var/log/msiempy/log.txt
timeout = 30
ssl_verify = no
output = text
```

You can initiate and configure the file with python cli.
```
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
Query events according to filters, loading the data with comprensive parralel tasks and printing relevant data.
```
events = msiempy.event.EventList(
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

### Disclaimer
This is an **UNOFFICIAL** project and is **NOT** sponsored or supported by **McAfee, Inc**. If you accidentally delete all of your datasources, don't call support (or me). Product access will always be limited to 'safe' methods and with respect to McAfee's intellectual property.
