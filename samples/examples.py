import msiempy

from msiempy.alarm import AlarmManager, Alarm
from msiempy.event import EventManager, Event, FieldFilter

session=msiempy.NitroSession(conf_path='../.msiem/conf.ini')
session.config.set('general', 'quiet', value='True')
alarm_1=''
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
    max_column_width=120,
    get_text_nest_attr=dict(fields=["ruleName","srcIp","destIp",'host', 'normId', 'normDesc', 'note']))) # Events fields

print('EVENT QUERY #1')
events = EventManager(
        time_range='LAST_3_DAYS',
        fields=['Alert.SrcIP'], # Alert.SrcIP is not queried by default
        filters=[
                FieldFilter('DstIP', ['0.0.0.0/0',]),
                FieldFilter('HostID', ['mail'], operator='CONTAINS')], # Please replace "mail" by a test hostname
        limit=10)

events.load_data()
print(events.get_text(fields=['Alert.LastTime','Alert.SrcIP', 'Rule.msg']))
