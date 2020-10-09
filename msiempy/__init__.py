# -*- coding: utf-8 -*-
"""

**The pythonic way to deal with the McAfee SIEM API**.  

Looking for a CLI tool? Checkout the `msiem CLI<https://github.com/mfesiem/msiem>`_  

Already know what you're looking for? Checkout the Class Hierarchy.    

Quick links: 

- `GitHub<https://github.com/mfesiem/msiempy>`_ 
- `PyPI<https://pypi.org/project/msiempy/>`_ 
- `Class diagram<https://mfesiem.github.io/docs/msiempy/classes.png>`_ 
- `Packages diagram<https://mfesiem.github.io/docs/msiempy/packages.png>`_
- `other SIEM API references<https://mfesiem.github.io>`_ (generated PDFs and other links)  

Table of content:

- `Installation`_
- `Authentication and configuration setup`_
- `A few usage exemples`_

        * `Execute an event query`_
        * `Acknowledge alarms`_
        * `Make direct API calls`_
        * `Add a note to events`_
        * `Fetch ESM infos`_
        * `Add a Datasource`_
        * `Add values to a Watchlist`_


Installation
============
Run::

        python3 -m pip install msiempy

Authentication and configuration setup
======================================

The module offers a single point of authentication against your SIEM, so you don't have to worry about authentication when writting your scripts. 
This means that you need to preconfigure the authentication using the configuration file.

The configuration file is located (by default) securely in your user directory since it contains credentials.  

- For Windows:  ``%APPDATA%\.msiem\conf.ini``
- For Mac :     ``$HOME/.msiem/conf.ini``  
- For Linux :   ``$XDG_CONFIG_HOME/.msiem/conf.ini`` or ``$HOME/.msiem/conf.ini``

Exemple::

        [esm]
        host = HOST
        user = USER
        passwd = PASSWORD's BASE64
        [general]
        verbose = no
        quiet = no
        logfile = /home/user/.msiem/log.txt
        timeout = 60
        ssl_verify = no


To set the password, you can use the `msiempy_setup.py<https://github.com/mfesiem/msiempy/blob/master/samples/msiempy_setup.py>`_ script.  
You can also directly paste the password's base64 in the config file by doing:  

>>> import base64
>>> passwd = 'P@assW0rd'
>>> print(base64.b64encode(passwd.encode('utf-8')).decode())
UEBhc3NXMHJk

A few usage exemples
====================

See also: 
        The `samples folder<https://github.com/mfesiem/msiempy/tree/master/samples>`_ for more, and/or review the `tests<https://github.com/mfesiem/msiempy/tree/master/tests>`_.     

Execute an event query 
----------------------

Query events according to destination IP and hostname filters, sorted by AlertID.  

>>> from  msiempy import EventManager, FieldFilter
>>> print('Simple event query sorted by AlertID')
>>> events = EventManager(
        time_range='CURRENT_YEAR',
        fields=['SrcIP', 'AlertID'], # SrcIP and AlertID are not queried by default
        filters=[
                FieldFilter('DstIP', ['0.0.0.0/0',]),
                FieldFilter('HostID', ['mail'], operator='CONTAINS')], # Replace "mail" by a test hostname
        order=(('ASCENDING', 'AlertID')),
        limit=10) # Will only load 10 events (per query)
>>> events.load_data()
>>> print(events)
>>> print(events.get_text(fields=['AlertID','LastTime','SrcIP', 'Rule.msg']))

Notes: 
        - The ``limit`` argument should be increased to 500 or 1000 once finish testing for better performance.  
        - Dump full list of fields usable in query `msiempy.event.FieldFilter` with `dump_all_fields.py<https://github.com/mfesiem/msiempy/blob/master/samples/dump_all_fields.py>`_ script.  

See: 
        Objects `msiempy.event.EventManager` and `msiempy.event.FieldFilter`

Acknowledge alarms
------------------

Print all ``unacknowledged`` alarms filtered by alarm name and event message

match} ``'Test alarm'`` and triggering event message match ``'Wordpress'``.  
Then acknowledge the alarms.  

>>> from msiempy import AlarmManager, Alarm
# Make an alarm query
>>> alarms=AlarmManager(
        time_range='CURRENT_YEAR',
        status_filter='unacknowledged', # passed to alarmGetTriggeredAlarms
        filters=[('alarmName', 'Test alarm')], # Regex  
        event_filters=[('ruleName','Wordpress')], # Regex  
        page_size=5 # Will only load 5 alarms (per page)  
) 
# Load the data into the list
>>> alarms.load_data() 
# Print results
>>> print("Alarm list: ")
>>> print(alarms)
>>> print(alarms.get_text(
        fields=['id','triggeredDate','acknowledgedDate', 'alarmName', 'acknowledgedUsername']))
# Acknowledge alarms
>>> print("Acknowledge alarms")
>>> for alarm in alarms:
        alarm.acknowledge()

Notes: 
        - The ``page_size`` argument should be increased to 500 or 1000 once finish testing for better performance.  

        - The `msiempy.alarm.AlarmManager` filtering feature is an addon to what the SIEM API offers, filters are applied locally as regular expressions.  

See: 
        Objects `msiempy.alarm.AlarmManager` and `msiempy.alarm.Alarm`

Make direct API calls
---------------------

This is useful when dealing with features of the ESM API that are not explicitly implemented in this library yet (i.e. user managment).  

**Use the session object** to make direct API calls with any data. 

>>> from msiempy import NitroSession
>>> s = NitroSession()
>>> s.login()
# Get all last 24h alarms details with ESM API v2 (not supported yet)  
>>> alarms = s.api_request('v2/alarmGetTriggeredAlarms?triggeredTimeRange=LAST_24_HOURS&status=&pageSize=500&pageNumber=1')
>>> for a in alarms:
        a.update(s.api_request('v2/notifyGetTriggeredNotificationDetail', {'id':a['id']}))

The session object will handle authentication and intermittent (but annoying) SIEM errors.  

See: 
        Object `msiempy.core.session.NitroSession`

Add a note to events
--------------------

Set the note of 2 events and check if the note is well set.  

>>> from  msiempy import EventManager, Event
>>> events = EventManager(
        time_range='CURRENT_YEAR',
        limit=2 )
>>> events.load_data()
>>> for event in events :
        event.set_note("Test note")
        event.refresh(use_query=False) # Event data will be loaded with ipsGetAlertData API method
        assert "Test note" in genuine_event['note'], "Error, the note hasn't been added"

See: 
        - `add_wpsan_note.py<https://github.com/mfesiem/msiempy/blob/master/samples/add_wpsan_note.py>`_ script for more on how to add notes to event that triggered alarms.   

        - Object `msiempy.event.Event`

Fetch ESM infos
---------------

Print a few esm infos. ESM object has not state for it self, it's a simple interface to data structures / values returned by the SIEM.  

>>> from msiempy import ESM
>>> esm=ESM()
>>> esm.version()
'11.2.1'
>>> esm.recs()
[('ERC-1', 144116287587483648)]
>>> esm.buildstamp()
'11.2.1 20190725050014'

See: 
        Object `msiempy.device.ESM`

Add a Datasource 
----------------

>>> from msiempy import DevTree
>>> devtree = DevTree()
>>> devtree.add({
        "name": "Test DS",
        "parent_id": "144116287587483648",
        "ds_ip": "10.2.2.2",
        "hostname": "testds.domain.ca",
        "type_id": "65"
}) 
{'value': 1385420} # Wait a bit for the request
>>> devtree.refresh() # Refresh the DevTree

See: 
        Objects `msiempy.device.DevTree` and `msiempy.device.DataSource`

Note: 
        `msiempy.device.DevTree.add` do not ensure the Datasource is well added, the methods returns a `dict` with the request ID fetched from the SIEM.
        There is still place for improvment `#82<https://github.com/mfesiem/msiempy/issues/82>`_.  

Add values to a Watchlist
-------------------------

>>> wl_list = WatchlistManager()
>>> wl = wl_list.search('test_Watchlist')[0]
>>> wl.add_values(['1.1.1.2', '2.2.2.1', '3.3.3.1'])

See: 
        Objects `msiempy.watchlist.WatchlistManager`, `msiempy.watchlist.Watchlist`
        
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
from .__version__ import __version__ as VERSION