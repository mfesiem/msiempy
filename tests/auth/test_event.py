import msiempy.event
from msiempy.utils import format_esm_time
import unittest


class T(unittest.TestCase):

    def test_query(self):

        events = msiempy.event.EventManager(
                    fields=['HostID', 'UserIDSrc', 'Alert.HostIDCat', 'Alert.UserIDSrcCat'],
                    time_range='LAST_24_HOURS',
                    filters=('SrcIP', ['10.0.0.0/8',]),
                    limit=100,
                    query_rec=0
                )
        events.load_data()
        for e in events :
            self.assertRegex(e['Alert.SrcIP'],'^10.','Filtering is problematic')
        print(events.json)
        

    def test_query_splitted(self):
        events = msiempy.event.EventManager(
            filters=[msiempy.query.GroupFilter(
                msiempy.event.FieldFilter('DstIP', ['10.0.0.0/8']),
                msiempy.event.FieldFilter('SrcIP', ['10.0.0.0/8']),
                logic='AND'
                )],
            time_range='LAST_24_HOURS',
            limit=50,
            query_rec=2
        )
        events.load_data()
        for e in events :
            self.assertRegex(e['Alert.SrcIP'],'^10.','Filterring in a reccursive query is problematic')
            self.assertRegex(e['Alert.DstIP'],'^10.','Filterring in a reccursive query is problematic')

        print('\n\n\nList len : '+str(len(events)))

    def test_add_note(self):

        events = msiempy.event.EventManager(
            filters=[('SrcIP', ['10.176.129.119']), ('NormID', ['408944640'])],
            time_range='LAST_24_HOURS',
            limit=20,
            query_rec=0
        )
        events.load_data()
        print(events.keys)
        print(events)

        for event in events :
            event.add_note("Test note ! ")