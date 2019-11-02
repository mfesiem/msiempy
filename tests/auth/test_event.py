import msiempy.event
from msiempy.__utils__ import format_esm_time
import unittest


class T(unittest.TestCase):

    def test_query(self):

        events = msiempy.event.EventManager(
                    time_range='LAST_3_DAYS',
                    fields=['HostID', 'UserIDSrc', 'Alert.HostIDCat', 'Alert.SrcIP'],
                    #filters=[('SrcIP', ['0.0.0.0/0',])],
                    #filters=[msiempy.query.FieldFilter('SrcIP', ['0.0.0.0/0',])],
                    limit=10,
                    max_query_depth=0
                )
        events.load_data()

        for e in events :
            self.assertNotEqual(e['Alert.SrcIP'],'',"An event doesn't have proper source IP")

        self.assertGreater(len(events),0)

        print('EVENTS KEYS\n'+str(events.keys))
        print('EVENTS TEXT\n'+str(events))
        print('EVENT JSON\n'+events.json)
            
        

    def test_query_splitted(self):
        events = msiempy.event.EventManager(
            filters=[msiempy.event.GroupFilter(
                [msiempy.event.FieldFilter(name='DstIP', values=['0.0.0.0/0']),
                msiempy.event.FieldFilter(name='SrcIP', values=['0.0.0.0/0'])],
                logic='AND'
                )],
            fields=['HostID', 'UserIDSrc', 'Alert.HostIDCat', 'Alert.SrcIP'],
            time_range='LAST_3_DAYS',
            limit=5,
            max_query_depth=1
        )
        events.load_data(delta='12h', slots=2)

        for e in events :
             self.assertNotEqual(e['Alert.SrcIP'],"An event doesn't have proper source IP")
            #self.assertRegex(e['Alert.SrcIP'],'^10.','Filterring in a reccursive query is problematic')
            #self.assertRegex(e['Alert.DstIP'],'^10.','Filterring in a reccursive query is problematic')

        self.assertGreater(len(events),0)
        print('EVENTS KEYS\n'+str(events.keys))
        print('EVENTS TEXT\n'+str(events))
        #print('EVENT JSON\n'+events.json)

    def test_add_note(self):
        #to refactor

        events = msiempy.event.EventManager(
            filters=[('SrcIP', ['0.0.0.0/0']),], # ('NormID', ['408944640'])],
            time_range='LAST_3_DAYS',
            limit=2,
            max_query_depth=0
        )
        events.load_data()
        print('EVENTS KEYS\n'+str(events.keys))
        print('EVENTS TEXT\n'+str(events))

        for event in events :
            event.add_note("Test note ! ")
            print("A test note has been added to the event : \n"+str(event.json))