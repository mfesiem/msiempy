import msiempy.event
import unittest


class T(unittest.TestCase):

    def test(self):

        events = msiempy.event.EventManager(
                    time_range='LAST_24_HOURS',
                    #compute_time_range=False,
                    #fields=['SrcIP', 'DstIP', 'SigID', 'LastTime'],
                    #limit=5,
                    filters=('SrcIP', ['0.0.0.0/0',]),
                    #sub_query=1
                )

        events.load_data()
        print(events.text)
        print('Len events : {}'.format(len(events)))

        #for e in events :
        #    self.assertRegex(e['Alert.SrcIP'],'^10.|^207.','sub_query filtering is problematic')