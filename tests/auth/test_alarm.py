import msiempy.alarm
import unittest


class T(unittest.TestCase):

    def test(self):

        alarms = msiempy.alarm.AlarmManager(
                    start_time='2019-05-20',
                    end_time='2019-05-20T12:00',
                    query_depth=0
                )
        print(alarms.filters)
        alarms.load_data()
        #print(alarms.text)

        print(alarms.json)

        print('Len alarms : {}'.format(len(alarms)))
        #just the first alarms's events details

        alarms.perform(
            msiempy.alarm.Alarm.action_load_events_details,
            pattern=list(alarms),
            asynch=True,
            progress=True)

        print(alarms.json)