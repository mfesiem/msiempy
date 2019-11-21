import msiempy

from msiempy.alarm import AlarmManager

session=msiempy.NitroSession(conf_path='../.msiem/conf.ini')
session.config.set('general', 'quiet', value='True')

alarms=AlarmManager(
        time_range='CURRENT_YEAR',
        status_filter='unacknowledged',
        filters=[
                ('alarmName', 'Test alarm')],
        event_filters=[
                ('ruleMessage','Postfix')],
        page_size=10)

print('#0')
result_qry_load_data = alarms.qry_load_data(
    workers=5, # Number of asych workers default 10
    alarms_details=True, 
    events_details=True, 
    use_query=False, 
    extra_fields=[], 
    page_number=1
)
print(result_qry_load_data)

print('#1')
print(alarms.load_data(pages=3, alarms_details=False).get_text(
    fields=['triggeredDate','acknowledgedDate', 'alarmName']))

print('#2')
print(alarms.load_data(pages=3, events_details=False).get_text(
    fields=['triggeredDate','acknowledgedDate','alarmName','iocId','events']))

print('#3')
alarms_events_use_query=AlarmManager(
        time_range='CURRENT_YEAR',
        filters=[
                ('alarmName', 'Test alarm')],
        event_filters=[
                ('Rule.msg','Postfix')],
        page_size=10)
print(alarms_events_use_query.load_data(pages=3, use_query=True, extra_fields=['SrcIP']).get_text(
    fields=['triggeredDate','acknowledgedDate','alarmName','events']))

print('#4')
print(alarms.load_data(pages=3).get_text(fields=['triggeredDate','alarmName','events']))

from msiempy.event import EventManager