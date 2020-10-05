import unittest
import json
from msiempy import Alarm, AlarmManager

def get_testing_data(data="./tests/local/test-alarms.json"):
    return json.load(open(data, "r"))

class T(unittest.TestCase):

    def test_event_match(self):

        alarms = AlarmManager(get_testing_data())
        
        res = alarms.search('52.167.119.2', fields='events')

        alarms.event_filters=[('srcIp','52.167.119.2')]

        for r in res :
            self.assertTrue(alarms._event_match(r))

        alarms.event_filters=[('srcIp','10.1.1.1')]

        for r in res :
            self.assertFalse(alarms._event_match(r))

    def test_alarm_match(self):
    
        alarms = AlarmManager(get_testing_data())
        
        res = alarms.search('User Logon', fields='alarmName', )

        alarms.alarm_filters=[('alarmName','User Logon')]
        
        for r in res :
            self.assertTrue(alarms._alarm_match(r))

