import msiempy.event
from msiempy.utils import format_esm_time
import unittest


class T(unittest.TestCase):

    def test_query(self):

        events = msiempy.event.EventManager(
                    time_range='LAST_24_HOURS',
                    filters=('SrcIP', ['10.0.0.0/8',]),
                    limit=100,
                    query_rec=0
                )
        events.load_data()
        for e in events :
            self.assertRegex(e['Alert.SrcIP'],'^10.','Filtering is problematic')

    def test_query_splitted(self):
        events = msiempy.event.EventManager(
            fields=['SrcIP', 'DstIP', 'SigID', 'LastTime'],
            filters=[msiempy.query.GroupFilter(
                msiempy.event.FieldFilter('DstIP', ['10.0.0.0/8']),
                msiempy.event.FieldFilter('SrcIP', ['10.0.0.0/8']),
                logic='AND'
                )],
            time_range='LAST_24_HOURS',
            limit=500,
            query_rec=2
        )
        events.load_data()
        for e in events :
            self.assertRegex(e['Alert.SrcIP'],'^10.','Splitted query filtering is problematic')
            self.assertRegex(e['Alert.DstIP'],'^10.','Splitted query filtering is problematic')
        print('\n\n\nList len : '+str(len(events)))

        #for e in events :
        #    self.assertRegex(e['Alert.SrcIP'],'^10.|^207.','sub_query filtering is problematic')