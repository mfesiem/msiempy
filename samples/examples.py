import pprint
import time
import msiempy
from msiempy.alarm import AlarmManager, Alarm
from msiempy.event import EventManager, Event, FieldFilter
from msiempy.device import DevTree, DataSource, ESM
from msiempy.watchlist import WatchlistManager, Watchlist

# session=msiempy.NitroSession(conf_path='../.msiem/conf.ini', conf_dict={'general':{'quiet':'True'}})
# session.config.set('general', 'quiet', value='True')

def alarm_examples():

        # query declaration. Thies query doesn't use the "qryExecuteDetails" SIEM api call
        alarms=AlarmManager(
                time_range='CURRENT_YEAR',
                status_filter='unacknowledged',
                filters=[('alarmName', 'Test alarm')],
                event_filters=[('ruleName','Postfix')], 
                # 'ruleName' is the field name when retreiving events infos from 'ipsGetAlertData' SIEM api call. 
                #       `ipsGetAlertData` call is used by default when calling load_data method
                #       see ALARM QUERY #3 to get event infos from 'qryExecuteDetails' calls
                # "Postfix" is a test rule name (aka event name)
                page_size=5)

        print('ALARM QUERY #1 : Minimal alarm representation 3 pages')
        alarms.load_data(pages=3, alarms_details=False)
        print(alarms)    
        print(alarms.get_text(
        fields=['triggeredDate','acknowledgedDate', 'alarmName']))

        print('ALARM QUERY #2 : Complete alarm details, only string info for events')
        alarms.load_data(events_details=False)
        print(alarms)    
        print(alarms.get_text(
        fields=['triggeredDate','acknowledgedDate','alarmName','iocId','events']))

         # query declaration. Thies query will use the "qryExecuteDetails" SIEM api call !
        alarms_events_use_query=AlarmManager(
                time_range='CURRENT_YEAR',
                status_filter='unacknowledged',
                filters=[('alarmName', 'Test alarm')],
                event_filters=[('Rule.msg','Postfix')], 
                # 'Rule.msg' is declared as the filter fields because we intend to call load_data(use_query=True)
                #       use_query=True will trigger and handle "qryExecuteDetails" requests on the SIEM
                # "Postfix" is a test rule name (aka event name)
                page_size=5)
        print('ALARM QUERY #3 : Complete alarm details with queried events fields')
        alarms_events_use_query=AlarmManager(
                time_range='LAST_3_DAYS',
                filters=[
                        ('alarmName', 'Test alarm')],
                event_filters=[
                        ('Rule.msg','Postfix')], # Please replace "Postfix" by a test rule name (aka event name)
                page_size=5)
        alarms_events_use_query.load_data(use_query=True, extra_fields=Event.REGULAR_EVENT_FIELDS)
        print('#3.1 : AlarmManager str represetation')
        print(alarms_events_use_query)
        print('#3.2 : Events str representation')
        print(alarms_events_use_query[0].get('events'))
        print('#3.3 : Table representation')
        print(alarms_events_use_query.get_text(
        fields=['triggeredDate','acknowledgedDate','alarmName','events'], # Alarms fields
        get_text_nest_attr=dict(fields=["Rule.msg","Alert.SrcIP","Alert.DstIP"]))) # Events fields

        print('ALARM QUERY #4 : Complete alarm details and events details 3 pages')
        alarms.load_data(pages=3)
        print('#4.1 : AlarmManager str represetation')
        print(alarms)
        print('#4.2 : Events str representation')
        print(alarms[0].get('events'))
        print('#4.3 : Table representation')
        print(alarms.get_text(fields=['triggeredDate','alarmName','events'],
        max_column_width=80,
        get_text_nest_attr=dict(fields=["ruleName","srcIp","destIp",'host', 'normId', 'normDesc', 'note']))) # Events fields

        print('ALARM ACKNOWLEDGE/UNACKNOWLEDGE #1')

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


def event_examples():
        print('EVENT QUERY #1 : Simple event query sorted by AlertID')
        events = EventManager(
                time_range='LAST_3_DAYS',
                fields=['SrcIP', 'AlertID'], # SrcIP and AlertID are not queried by default
                filters=[
                        FieldFilter('DstIP', ['0.0.0.0/0',]),
                        FieldFilter('HostID', ['mail'], operator='CONTAINS')], # Please replace "mail" by a test hostname
                order=(('ASCENDING', 'AlertID')),
                limit=10)
        
        events.load_data()
        print(events)
        print(events.get_text(fields=['AlertID','LastTime','SrcIP', 'Rule.msg']))

        print('EVENT QUERY #2 : Deeper event query')
        events = msiempy.event.EventManager(
            time_range='LAST_3_DAYS',
            fields=['SrcIP', 'AlertID'], # SrcIP and AlertID are not queried by default
            limit=3
        )
        events.load_data(slots=3, max_query_depth=1)
        print(events)
        print(events.get_text(fields=['AlertID','LastTime','SrcIP', 'Rule.msg']))

def devtree_exaples():
        print('DEVTREE #1 : Simple devtree printing')
        devtree = DevTree()
        print(devtree)
        print(devtree.get_text(format='csv'))
        print(devtree.get_text(format='prettytable', fields=['ds_ip', 'client', 'last_time','model','name','parent_name','vendor']))
        print('len : {}'.format(len(devtree)))
        print('__iter__ print')
        [ print (str(f)[:80]+'.[..]') for f in devtree ]
        # print('repr : {}'.format(repr(devtree)))
        
        print('DEVTREE #2 : Add a DataSource')
        # Find the first device that's a receiver to use as the DataSource parent
        ds_config = {}
        for ds in devtree:
            if ds['desc_id'] in ['2', '13']:
                ds_config['parent_id'] = ds['ds_id']
            
        ds_config['name'] = 'msiempy_test_datasource_delete_me'
        ds_config['ds_ip'] = '0.20.5.5'
        ds_config['type_id'] = '65'
        print('Adding datasource...')
        print('Result ID: ', devtree.add(ds_config))

        print('DEVTREE #2.1 : DataSource details...')
        ds = devtree.search('msiempy_test_datasource_delete_me')
        if ds:
            ds.load_details()
        else:
            print('New datasource not found. Waiting 15 seconds and rechecking...')
            time.sleep(15)
            devtree.refresh()
            ds = devtree.search('msiempy_test_datasource_delete_me')
            if ds:
                ds.load_details()

        print('DETAILS: {}'.format(ds.json))

        print('DEVTREE #3 : Deleting DataSource')
        for ds in devtree:
                if ds['name'] == 'msiempy_test_datasource_delete_me':
                        print('Test datasource found. Deleting...')
                        ds = devtree[ds['idx']]
                        ds.delete()
                        continue

        print('DEVTREE #3.1 : Verifying the datasource is gone')
        for ds in devtree:
                assert ds['name']!='msiempy_test_datasource_delete_me', "Looks like the datasource is still here :/"


def esm_examples():
        print('ESM #1 : Simple ESM status printing')
        esm = ESM()
        pprint.pprint(esm.status())
        # ...
        pass

def watchlist_examples():
        print('WATCHLIST #1 : Simple Wlist printing')
        wlist = WatchlistManager()
        print(wlist.text)
        # ...
        pass
#Main
# alarm_examples()
# event_examples()

# esm_examples()
# watchlist_examples()

devtree_exaples()