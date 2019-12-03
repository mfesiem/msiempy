import pprint
import msiempy
from msiempy.alarm import AlarmManager, Alarm
from msiempy.event import EventManager, Event, FieldFilter
from msiempy.device import DevTree, DataSource, ESM
from msiempy.watchlist import WatchlistManager, Watchlist

session=msiempy.NitroSession(conf_path='../.msiem/conf.ini', conf_dict={'general':{'quiet':'True'}})
#session.config.set('general', 'quiet', value='True')

def alarm_examples():

        alarms=AlarmManager(
                time_range='CURRENT_YEAR',
                status_filter='unacknowledged',
                filters=[('alarmName', 'Test alarm')],
                event_filters=[('ruleName','Postfix')], # Please replace "Postfix" by a test rule name (aka event name)
                page_size=3)

        print('ALARM QUERY #1 : Minimal alarm representation')
        alarms.load_data(pages=3, alarms_details=False)
        print(alarms)    
        print(alarms.get_text(
        fields=['triggeredDate','acknowledgedDate', 'alarmName']))

        print('ALARM QUERY #2 : Complete alarm details, only string info for events')
        alarms.load_data(events_details=False)
        print(alarms)    
        print(alarms.get_text(
        fields=['triggeredDate','acknowledgedDate','alarmName','iocId','events']))


        print('ALARM QUERY #3 : Complete alarm details with queried events fields')
        alarms_events_use_query=AlarmManager(
                time_range='LAST_3_DAYS',
                filters=[
                        ('alarmName', 'Test alarm')],
                event_filters=[
                        ('Rule.msg','Postfix')], # Please replace "Postfix" by a test rule name (aka event name)
                page_size=10)
        alarms_events_use_query.load_data(use_query=True, extra_fields=Event.REGULAR_EVENT_FIELDS)
        print('#3.1 : AlarmManager str represetation')
        print(alarms_events_use_query)
        print('#3.2 : Events str representation')
        print(alarms_events_use_query[0].get('events'))
        print('#3.3 : Table representation')
        print(alarms_events_use_query.get_text(
        fields=['triggeredDate','acknowledgedDate','alarmName','events'], # Alarms fields
        get_text_nest_attr=dict(fields=["Rule.msg","Alert.SrcIP","Alert.DstIP"]))) # Events fields

        print('ALARM QUERY #4 : Complete alarm details and events details')
        alarms.load_data(pages=3)
        print('#4.1 : AlarmManager str represetation')
        print(alarms)
        print('#4.2 : Events str representation')
        print(alarms[0].get('events'))
        print('#4.3 : Table representation')
        print(alarms.get_text(fields=['triggeredDate','alarmName','events'],
        max_column_width=80,
        get_text_nest_attr=dict(fields=["ruleName","srcIp","destIp",'host', 'normId', 'normDesc', 'note']))) # Events fields

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
        print(events.get_text(fields=['AlertID','LastTime','SrcIP', 'Rule.msg']))

        print('EVENT QUERY #2 : Deeped event query')
        events = msiempy.event.EventManager(
            time_range='LAST_3_DAYS',
            fields=['SrcIP', 'AlertID'], # SrcIP and AlertID are not queried by default
            limit=3,
            max_query_depth=1
        )
        events.load_data(slots=3)
        print(events.get_text(fields=['AlertID','LastTime','SrcIP', 'Rule.msg']))

def devtree_exaples():
        print('DEVTREE #1 : Simple devtree printing')
        devtree = DevTree()
        print(devtree)
        print(devtree.get_text(format='csv'))
        print(devtree.get_text(format='prettytable', fields=['ds_ip', 'client', 'last_time','model','name','parent_name','vendor']))

        # ...

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
alarm_examples()
event_examples()
devtree_exaples()
esm_examples()
watchlist_examples()