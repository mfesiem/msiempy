import msiempy.alarm
import unittest


class T(unittest.TestCase):

   
    def test_query(self):
        for alarm in msiempy.alarm.AlarmManager(time_range='LAST_HOUR', status_filter='unacknowledged').load_data():
            self.assertEqual(alarm['acknowledgedDate'],  '')
            self.assertEqual(alarm['acknowledgedUsername'], None)

        for alarm in (msiempy.alarm.AlarmManager(
            time_range='LAST_24_HOURS',
            filters=[('alarmName', 'High Severity Event'),
                ('severity', [80,85,90,95,100]),
                ('ruleMessage', 'HTTP'),
                ('destIp', '10.165')],
            query_rec=0,
            page_size=500
            ).load_data()) :

            self.assertRegex(alarm['alarmName'], 'High Severity Event', 'Filtering alarms is not working')
            self.assertRegex(str(alarm['severity']), '80|85|90|95|100', 'Filtering alarms is not working')
            self.assertRegex(str(alarm['events'][0]['ruleMessage']), 'HTTP', 'Filtering alarms is not working')
            self.assertRegex(str(alarm['events'][0]['destIp']), '10.165', 'Filtering alarms is not working')


    def test_get_event_details(self):

        alarms = msiempy.alarm.AlarmManager(
            time_range='LAST_24_HOURS',
            query_rec=0,
            page_size=500
        )
        
        alarms_with_event_summary = alarms.load_data()
        alarms_with_genuine_events = alarms.load_events() #No need the re-call load_data() cause alrealy called on alarms

        self.assertEqual(len(alarms_with_event_summary), len(alarms_with_genuine_events), "The two lists doesn't have the same lenght")
        for i in range(len(alarms)):
            self.assertEqual(alarms_with_event_summary[i]['alarmName'], alarms_with_genuine_events[i]['alarmName'], 'Loading events changed list order')
            if len(alarms_with_event_summary[i]['events']) >0:
                event_sum=alarms_with_event_summary[i]['events'][0]
                event_genuine=alarms_with_genuine_events[i]['events'][0]
                self.assertEqual(event_sum['ruleMessage'], event_genuine['Rule.msg'], 'getting event details is in trouble')

        print(alarms)



