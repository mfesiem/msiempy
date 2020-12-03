[![Nitro Logo](https://avatars0.githubusercontent.com/u/50667087?s=200&v=4)](https://mfesiem.github.io/docs/msiempy/msiempy.html)

McAfee SIEM API Python wrapper
==============================

[![image](https://github.com/mfesiem/msiempy/workflows/test/badge.svg)](https://github.com/mfesiem/msiempy/actions)
[![image](https://codecov.io/gh/mfesiem/msiempy/branch/master/graph/badge.svg)](https://codecov.io/gh/mfesiem/msiempy)
[![image](https://badge.fury.io/py/msiempy.svg)](https://pypi.org/project/msiempy)
[![image](https://img.shields.io/badge/-documentation-blue)](https://mfesiem.github.io/docs/msiempy/msiempy.html)

This module aims to provide a simple API wrapper around the McAfee SIEM
API principal components. Code design is accessible and pythonic via
list-like and dict-like objects interfaces.

Main features
=============

-   [ESM](https://mfesiem.github.io/docs/msiempy/msiempy.ESM.html)
    operations: monitor, show statuses
-   [DataSource](https://mfesiem.github.io/docs/msiempy/msiempy.DataSource.html)
    operations, via
    [DevTree](https://mfesiem.github.io/docs/msiempy/msiempy.DevTree.html):
    add, edit, delete - including client datasources, retreive from ID
-   [Alarm](https://mfesiem.github.io/docs/msiempy/msiempy.Alarm.html)
    operations and querying, via
    [AlarmManager](https://mfesiem.github.io/docs/msiempy/msiempy.AlarmManager.html):
    filter, load pages, acknowledge, unacknowledge, delete, get
    triggering event, retreive from ID
-   [Event](https://mfesiem.github.io/docs/msiempy/msiempy.Event.html)
    operations and querying, via
    [EventManager](https://mfesiem.github.io/docs/msiempy/msiempy.EventManager.html)
    and
    [GroupedEventManager](https://mfesiem.github.io/docs/msiempy/msiempy.GroupedEventManager.html):
    group queries, filter, add fields, set event\'s note, retreive from
    ID
-   [Watchlist](https://mfesiem.github.io/docs/msiempy/msiempy.Watchlist.html)
    operations, via
    [WatchlistManager](https://mfesiem.github.io/docs/msiempy/msiempy.WatchlistManager.html):
    list, add/remove watchlists, add/remove values, get values, retreive
    from ID
-   Make direct API calls, via
    [NitroSession](https://mfesiem.github.io/docs/msiempy/msiempy.NitroSession.html)

(*Links are directing to the latest documentation version*)

Known module implementations
============================

-   msiem CLI : [CLI tools for ESM](https://github.com/mfesiem/msiem)
-   esm_healthmon : [Monitors ESM
    operations](https://github.com/andywalden/esm_healthmon)
-   track-host: [Rapidly request event logs to track a
    workstation](https://github.com/mfesiem/track-host)
-   See [samples
    folder](https://github.com/mfesiem/msiempy/tree/master/samples) or
    the [tests](https://github.com/mfesiem/msiempy/tree/master/tests).
    for other implementation examples and scripts !

Installation
============

    pip install -U msiempy

Documentation
=============

Read the latest [documentation](https://mfesiem.github.io/docs/msiempy/msiempy.html).

Authentication and configuration setup
======================================

The module offers a single point of authentication against your SIEM, so
you don\'t have to worry about authentication when writting your
scripts. This means that you need to preconfigure the authentication
using the configuration file.

The configuration file is located (by default) securely in your user
directory since it contains credentials.

-   For Windows: `%APPDATA%\.msiem\conf.ini`
-   For Mac : `$HOME/.msiem/conf.ini`
-   For Linux : `$XDG_CONFIG_HOME/.msiem/conf.ini` or
    `$HOME/.msiem/conf.ini`

Exemple:

    [esm]
    # Your ESM credentials
    host = HOST
    user = USER
    passwd = PASSWORD's BASE64
    [general]
    # Verbosity
    verbose = no
    quiet = no
    # Path to a logfile, the logfile output will always be verbose
    logfile = 
    # Misc 
    timeout = 60
    ssl_verify = no

To set the password, you can use the
[msiempy_setup.py](https://github.com/mfesiem/msiempy/blob/master/samples/msiempy_setup.py)
script. You can also directly paste the password\'s base64 in the config
file by doing:

```python
>>> import base64 
>>> passwd = 'P@assW0rd'
>>> print(base64.b64encode(passwd.encode('utf-8')).decode()) 
UEBhc3NXMHJk
```

Changelog
=========

Please refer to the
[releases](https://github.com/mfesiem/msiempy/releases) github page.

Contribute
==========

Pull requests are welcome!

Please read the [contributing](https://github.com/mfesiem/msiempy/blob/master/CONTRIBUTING.md) file.

Disclaimer
==========

This is an **UNOFFICIAL** project and is **NOT** sponsored or supported
by **McAfee, Inc**. If you accidentally delete all of your datasources,
don\'t call support (or us). Product access will always be in respect to
McAfee\'s intellectual property.
