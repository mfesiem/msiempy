import msiempy.alarm
import unittest


class T(unittest.TestCase):


    def test_print(self):
        alarms = msiempy.alarm.AlarmManager(
            time_range='CURRENT_YEAR',
            max_query_depth=0,
            page_size=10)

        print(alarms.__dict__)

        alarms.load_data()
        
        print('ALARMS JSON\n'+str(alarms.json))
        print('ALARMS TEXT\n'+str(alarms))
        print('ALARMS KEYS\n'+str(alarms.keys))

        self.assertGreater(len(alarms),0)
   
    def test_query(self):

        alarms=msiempy.alarm.AlarmManager(time_range='CURRENT_YEAR', status_filter='unacknowledged', max_query_depth=0, page_size=50).load_data()
        self.assertGreater(len(alarms),0)

        for alarm in alarms:
            self.assertEqual(alarm['acknowledgedDate'],  '')
            self.assertEqual(alarm['acknowledgedUsername'], None)

        alarms = msiempy.alarm.AlarmManager(
            time_range='CURRENT_YEAR',
            filters=[
                ('severity', [50, 80,85,90,95,100]),
                #('ruleMessage', 'HTTP'),
                ('sourceIp', ['1','2','3'])],
            max_query_depth=0,
            page_size=50
            ).load_data(workers=20)

        self.assertGreater(len(alarms),0)

        for alarm in alarms :
            #self.assertRegex(alarm['alarmName'], 'High Severity Event', 'Filtering alarms is not working')
            self.assertRegex(str(alarm['severity']), '10|25|50|80|85|90|95|100', 'Filtering alarms is not working')
            #self.assertRegex(str(alarm['events'][0]['ruleMessage']), 'HTTP', 'Filtering alarms is not working')
            self.assertRegex(str(alarm['events'][0]['sourceIp']), '1|2|3', 'Filtering alarms is not working')

    def test_get_event_details(self):

        alarms = msiempy.alarm.AlarmManager(
            time_range='CURRENT_YEAR',
            max_query_depth=0,
            page_size=10
        )
        
        alarms_with_event_summary = alarms.load_data()
        alarms_with_genuine_events = alarms.load_events() #No need the re-call load_data() cause alrealy called on alarms
        alarms_with_alert_data_events=alarms.load_events(by_id=True)

        self.assertGreater(len(alarms_with_event_summary),0)
   
        self.assertEqual(len(alarms_with_event_summary), len(alarms_with_genuine_events), "The two lists doesn't have the same lenght")
        for i in range(len(alarms)):
            self.assertEqual(alarms_with_event_summary[i]['alarmName'], alarms_with_genuine_events[i]['alarmName'], 'Loading events changed list order')
            if len(alarms_with_event_summary[i]['events']) >0:
                event_sum=alarms_with_event_summary[i]['events'][0]
                event_genuine=alarms_with_genuine_events[i]['events'][0]
                self.assertEqual(event_sum['ruleMessage'], event_genuine['Rule.msg'], 'getting event details is in trouble')

        print('ALARMS WITH EVENT SUM\n'+str(alarms_with_event_summary))
        print('ALARMS WITH GENUINE EVENTS\n'+str(alarms_with_genuine_events))
        print('ALARMS WITH ALERT DATA EVENTS\n'+str(alarms_with_alert_data_events))



