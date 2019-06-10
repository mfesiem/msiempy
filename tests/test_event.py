import msiempy.event
from msiempy.utils import format_esm_time
import unittest


class T(unittest.TestCase):

    def test(self):

        events = msiempy.event.EventManager(
                    time_range='LAST_24_HOURS',
                    filters=('SrcIP', ['207.0.0.0/8',]),
                )
        """
        events = msiempy.event.EventManager(
                    #start_time='06/09/2019 12:03:16',
                    #end_time='06/09/2019 12:03:18',
                    #time_range='LAST_24_HOURS',
                    #filters=[
                        #('DSIDSigID', ['143-2317843039',]),]
                        #('Description', ["""51: Retrieve File"""]),]
                        #msiempy.event.FieldFilter('LastTime', [format_esm_time('06-10-2019T12:02:56')], operator='GREATER_THAN')],
                )"""

        print(events.filters)
        events.load_data()
        print(events.text)
        print('Len events : {}'.format(len(events)))

        #for e in events :
        #    self.assertRegex(e['Alert.SrcIP'],'^10.|^207.','sub_query filtering is problematic')