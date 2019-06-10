import msiempy.event
import unittest


class T(unittest.TestCase):

    def test(self):

        events = msiempy.event.EventManager(
                    time_range='LAST_24_HOURS',
                    filters=('SrcIP', ['207.0.0.0/8',]),
                )

        print(events.filters)
        events.load_data()
        print(events.text)
        print('Len events : {}'.format(len(events)))

        #for e in events :
        #    self.assertRegex(e['Alert.SrcIP'],'^10.|^207.','sub_query filtering is problematic')