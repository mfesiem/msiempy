# -*- coding: utf-8 -*-
"""
**The pythonic way to deal with the McAfee SIEM API**

.. image:: https://avatars0.githubusercontent.com/u/50667087?s=200&v=4
        :target: https://mfesiem.github.io/docs/msiempy/msiempy.html
        :alt: Nitro
        :width: 50
        :height: 50

Welcome to the **msiempy** library documentation. 

Looking for a CLI tool? Checkout the `msiem CLI <https://github.com/mfesiem/msiem>`_  

Already know what you're looking for?
Checkout the `Module Index <https://mfesiem.github.io/docs/msiempy/moduleIndex.html>`_.    
  
Quick links:
        - `GitHub | README.md <https://github.com/mfesiem/msiempy>`_
        - `Class diagram <https://mfesiem.github.io/docs/msiempy/classes.png>`_, (`Packages diagram <https://mfesiem.github.io/docs/msiempy/packages.png>`_)
        - `mfesiem.github.io <https://mfesiem.github.io>`_ (generated PDFs and other links)  

.. contents:: **Table of Contents**

Installation
============
Run::

        pip install msiempy

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


To set the password, you can use the `msiempy_setup.py <https://github.com/mfesiem/msiempy/blob/master/samples/msiempy_setup.py>`_ script.  
You can also directly paste the password's base64 in the config file by doing:  

>>> import base64
>>> passwd = 'P@assW0rd'
>>> print(base64.b64encode(passwd.encode('utf-8')).decode())
UEBhc3NXMHJk

A few usage exemples
====================

Execute an event query 
----------------------

Query events according to destination IP and hostname filters, sorted by AlertID.  

.. python::

        from  msiempy import EventManager, FieldFilter
        print('Simple event query sorted by AlertID')
        events = EventManager(
                time_range='CURRENT_YEAR',
                fields=['SrcIP', 'AlertID'], # SrcIP and AlertID are not queried by default
                filters=[
                        FieldFilter('DstIP', ['0.0.0.0/0',]),
                        FieldFilter('HostID', ['mail'], operator='CONTAINS')], # Replace "mail" by a test hostname
                order=(('ASCENDING', 'AlertID')),
                limit=10) # Will only load 10 events (per query)
        events.load_data()
        print(events)
        print(events.get_text(fields=['AlertID','LastTime','SrcIP', 'Rule.msg']))

Notes: 
        - The ``limit`` argument should be increased to 500 or 1000 once finish testing for better performance.  
        - Dump full list of fields usable in query `FieldFilter` with `dump_all_fields.py <https://github.com/mfesiem/msiempy/blob/master/samples/dump_all_fields.py>`_ script.  

See: 
        Objects `EventManager` and `FieldFilter`

Acknowledge alarms
------------------

Print all ``unacknowledged`` alarms filtered by alarm name and event message, then acknowledge the alarms.  

Filter with alarm match ``'Test alarm'`` and triggering event message match ``'Wordpress'``.  

.. python::

        from msiempy import AlarmManager, Alarm
        # Make an alarm query
        alarms=AlarmManager(
                time_range='CURRENT_YEAR',
                status_filter='unacknowledged', # passed to alarmGetTriggeredAlarms
                filters=[('alarmName', 'Test alarm')], # Regex  
                event_filters=[('ruleName','Wordpress')], # Regex  
                page_size=5 # Will only load 5 alarms (per page)  
        ) 
        # Load the data into the list
        alarms.load_data() 
        # Print results
        print("Alarm list: ")
        print(alarms)
        print(alarms.get_text(
                fields=['id','triggeredDate','acknowledgedDate', 'alarmName', 'acknowledgedUsername']))
        # Acknowledge alarms
        print("Acknowledge alarms")
        for alarm in alarms:
                alarm.acknowledge()

Notes: 
        - The ``page_size`` argument should be increased to 500 or 1000 once finish testing for better performance.  
        - The `AlarmManager` filtering feature is an addon to what the SIEM API offers, filters are applied locally as regular expressions.  

See: 
        Objects `AlarmManager` and `Alarm`

Make direct API calls
---------------------

This is useful when dealing with features of the ESM API that are not explicitly implemented in this library yet (i.e. user managment).  

**Use the session object** to make direct API calls with any data. 

.. python::

        from msiempy import NitroSession
        s = NitroSession()
        s.login()
        # Get all last 24h alarms details with ESM API v2 (not supported yet)  
        alarms = s.api_request('v2/alarmGetTriggeredAlarms?triggeredTimeRange=LAST_24_HOURS&status=&pageSize=500&pageNumber=1')
        for a in alarms:
                a.update(s.api_request('v2/notifyGetTriggeredNotificationDetail', {'id':a['id']}))

The session object will handle authentication and intermittent (but annoying) SIEM errors.  

See: 
        Object `NitroSession`

Add a note to events
--------------------

Set the note of 2 events and check if the note is well set.  

.. python::

        from  msiempy import EventManager, Event
        events = EventManager(
                time_range='CURRENT_YEAR',
                limit=2 )
        events.load_data()
        for event in events :
                event.set_note("Test note")
                event.refresh(use_query=False) # Event data will be loaded with ipsGetAlertData API method
                assert "Test note" in genuine_event['note'], "Error, the note hasn't been added"

See: 
        - `add_wpsan_note.py <https://github.com/mfesiem/msiempy/blob/master/samples/add_wpsan_note.py>`_ script for more on how to add notes to event that triggered alarms.   
        - Object `Event`

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
        Object `ESM`

Add a Datasource 
----------------

>>> from msiempy import DevTree
>>> devtree = DevTree()
>>> devtree.add({
...     "name": "Test DS",
...     "parent_id": "144116287587483648",
...     "ds_ip": "10.2.2.2",
...     "hostname": "testds.domain.ca",
...     "type_id": "65" }) 
{'value': 1385420} # Wait a bit for the request
>>> devtree.refresh() # Refresh the DevTree

See: 
        Objects `DevTree` and `DataSource`

Add values to a Watchlist
-------------------------

>>> from msiempy import WatchlistManager
>>> wl_list = WatchlistManager()
>>> wl = wl_list.search('test_Watchlist')[0]
>>> wl.add_values(['1.1.1.2', '2.2.2.1', '3.3.3.1'])

See: 
        Objects `WatchlistManager`, `Watchlist`

Execute a grouped event query
-----------------------------

Query the curent day events filtered by `IPSID` grouped by `ScrIP`.  

.. python::

        from msiempy import GroupedEventManager
        import pprint
        query = GroupedEventManager(
                        time_range='LAST_3_DAYS', 
                        field='SrcIP', 
                        filters=[('IPSID', '144116287587483648')]) 
        query.load_data()
        # Sort the results by total count
        results = list(reversed(sorted(query, key=lambda k: int(k['SUM(Alert.EventCount)']))))
        # Display top 10
        top10=results[:10]
        pprint.pprint(top10)


See:
        Objects `GroupedEventManager` and `GroupedEvent`.  

Tip:
        `all_dev.py script <https://github.com/mfesiem/msiempy/blob/master/samples/all_dev.py>`_ can help you list all your datasources IDs (for the required ``IPSID`` filter).  


And more...
-----------

See: 
        - The `samples folder <https://github.com/mfesiem/msiempy/tree/master/samples>`_ 
        - The `tests <https://github.com/mfesiem/msiempy/tree/master/tests>`_.     


Changelog
=========

Please refer to the `releases <https://github.com/mfesiem/msiempy/releases>`_ github page.  

Contribute
==========

Pull requests are welcome!  
        Please read the `contributing <https://github.com/mfesiem/msiempy/blob/master/CONTRIBUTING.md>`_ file.  


Code analysis
=============

.. image:: https://app.codacy.com/project/badge/Grade/114821fcf6e14b8eb0f927e0112488c8
        :target: https://www.codacy.com/gh/mfesiem/msiempy?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=mfesiem/msiempy&amp;utm_campaign=Badge_Grade
        :alt: Codacy Badge

.. image:: https://api.codeclimate.com/v1/badges/0cc21ba8f82394cb05f3/maintainability
        :target: https://codeclimate.com/github/mfesiem/msiempy/maintainability
        :alt: Code climate Maintainability

Error report
============

Configure log file reporting in the configuration file and and look for ``"ERROR"``.  
Useful shell command to get simple list of errors::  

        cat /path/to/your/log/file | grep -i error | sort | uniq


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