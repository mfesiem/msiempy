import msiempy.alarm
import unittest


class T(unittest.TestCase):

    def test(self):

        events = msiempy.alarm.AlarmManager(
                    start_time='2019-05-20',
                    end_time='2019-05-22'
                )


        print(events.filters)
        events.load_data()
        print(events.text)
        print(events.json)
        print('Len events : {}'.format(len(events)))

        #for e in events :
        #    self.assertRegex(e['Alert.SrcIP'],'^10.|^207.','sub_query filtering is problematic')