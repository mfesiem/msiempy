import msiempy.event
import unittest


class T(unittest.TestCase):

    def test(self):
        
        events = msiempy.event.EventManager(
                    fields=['SrcIP', 'DstIP', 'SigID', 'LastTime'],
                    filters=[msiempy.event.GroupFilter(
                        msiempy.event.FieldFilter('DstIP', ['10.0.0.0/8']),
                        msiempy.event.FieldFilter('SrcIP', ['10.0.0.0/8']),
                        logic='AND'
                        )],
                    limit=100,
                    sub_query=1
                )

        events.load_data()
        print(events.text)
        for e in events :
            self.assertRegex(e['SrcIP'],'^10.','sub_query filtering is problematic')