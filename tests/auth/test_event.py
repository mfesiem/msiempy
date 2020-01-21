import msiempy.event
from msiempy.__utils__ import format_esm_time, parse_timedelta, timerange_gettimes
import unittest
from datetime import datetime, timedelta

QUERY_TIMERANGE=300


class T(unittest.TestCase):

    def test_event(self):
        events = msiempy.event.EventManager(
                    time_range='CUSTOM',
                    start_time=datetime.now()-timedelta(days=QUERY_TIMERANGE),
                    end_time=datetime.now()+timedelta(days=1),
                    limit=1
                )
        events.load_data()
        event=events[0]

        id = event['IPSIDAlertID']

        event_from_ips_get_alert_data=msiempy.event.Event(id=id)
        self.assertEqual(event['IPSIDAlertID'], '|'.join(
            [str(event_from_ips_get_alert_data['ipsId']['id']),
            str(event_from_ips_get_alert_data['alertId'])]))
        
        if msiempy.NitroSession().api_v == 2 :
            print('CREATING EVENT MANUALLY FROM ID')
            #event_from_direct_id_query = msiempy.event.Event()
            data=msiempy.event.Event().data_from_id(id=id, use_query=True)
            event_from_direct_id_query=msiempy.event.Event(data)
            print('EVENT RETREIVED : {}'.format(event_from_direct_id_query))
            print('ORIGINAL EVENT : {}' .format(event))
            self.assertEqual(event_from_direct_id_query, data)

        self.assertTrue('msg' in event)

    def test_query(self):

        events = msiempy.event.EventManager(
                    time_range='CUSTOM',
                    start_time=datetime.now()-timedelta(days=QUERY_TIMERANGE),
                    end_time=datetime.now()+timedelta(days=1),
                    fields=msiempy.event.Event.REGULAR_EVENT_FIELDS,
                    limit=10
                )
        events.load_data()

        for e in events :
            self.assertNotEqual(e['Alert.SrcIP'],'',"An event doesn't have proper source IP")

        self.assertGreater(len(events),0)

        print('EVENTS KEYS\n'+str(events.keys))
        print('EVENTS TEXT\n'+str(events))
        print('EVENT JSON\n'+events.json)        

    def test_query_splitted(self):
        events_no_split = msiempy.event.EventManager(
            time_range='CUSTOM',
            start_time=datetime.now()-timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now()+timedelta(days=1),
            order=(('ASCENDING', 'AlertID')),
            limit=10
        )
        events_no_split.load_data()
        print('events_no_split'.upper())
        print(events_no_split.text)

        events = msiempy.event.EventManager(
            time_range='CUSTOM',
            start_time=datetime.now()-timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now()+timedelta(days=1),
            order=(('ASCENDING', 'AlertID')),
            limit=5,
            max_query_depth=1 # Generate warning and ignore
        )
        events.load_data(slots=2,  max_query_depth=1) # Works
        print('events_splitted'.upper())
        print(events.text)

        l1=events_no_split[:5]
        l2=events[:5]

        self.assertEqual(l1, l2, 'Firts part of the splitted query doesn\'t correspond to the genuine query. This can happen when some event are generated at the exact same moment the query is submitted, retry the test ?')

    def test_query_splitted_with_timedelta(self):
        events_no_split = msiempy.event.EventManager(
            time_range='CUSTOM',
            start_time=datetime.now()-timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now()+timedelta(days=1),
            order=(('ASCENDING', 'AlertID')),
            limit=10
        )
        events_no_split.load_data()
        print('events_no_split'.upper())
        print(events_no_split.text)

        events = msiempy.event.EventManager(
            time_range='CUSTOM',
            start_time=datetime.now()-timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now()+timedelta(days=1),
            order=(('ASCENDING', 'AlertID')),
            limit=5,
            max_query_depth=1 # Generate warning and ignore
        )
        events.load_data(slots=2,  max_query_depth=1) # Works
        print('events_splitted'.upper())
        print(events.text)

        l1=events_no_split[:5]
        l2=events[:5]

        self.assertEqual(l1, l2, 'Firts part of the splitted query doesn\'t correspond to the genuine query. This can happen when some event are generated at the exact same moment the query is submitted, retry the test ?')


    def test_filtered_query(self):
        qry_filters = [msiempy.event.GroupFilter(
            [msiempy.event.FieldFilter(name='DstIP', values=['0.0.0.0/0']),
            msiempy.event.FieldFilter(name='SrcIP', values=['0.0.0.0/0'])],
            logic='AND'
            )]
        
        #todo

    def test_ordered_query(self):
        events_no_split = msiempy.event.EventManager(
            time_range='CUSTOM',
            start_time=datetime.now()-timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now()+timedelta(days=1),
            fields=['Alert.AlertID'],
            order=(('ASCENDING', 'AlertID')),
            limit=10,
        )
        events_no_split.load_data()

        last_event=None
        for event in events_no_split :
            if not last_event :
                last_event=event
                continue
            self.assertGreater(int(event['Alert.AlertID']),int(last_event['Alert.AlertID']))
            last_event=event

    def test_add_note(self):

        events = msiempy.event.EventManager(
            time_range='CUSTOM',
            start_time=datetime.now()-timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now()+timedelta(days=1),
            limit=2
        )
        events.load_data()

        for event in events :
            event.set_note("Test note")
            genuine_event = msiempy.event.Event(id=event['IPSIDAlertID'])
            self.assertRegexpMatches(genuine_event['note'], "Test note", "The doesn't seem to have been added to the event \n"+str(event))

    def test_getitem(self):
        events = msiempy.event.EventManager(
            time_range='CUSTOM',
            start_time=datetime.now()-timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now()+timedelta(days=1),
            fields=msiempy.event.Event.REGULAR_EVENT_FIELDS,
            limit=5
        )
        events.load_data()

        print(events)

        print(events.get_text(fields=[
            "msg",
            "SrcIP",
            "DstIP", 
            "SrcMac",
            "DstMac",
            "NormID",
            "HostID",
            "UserIDSrc",
            "ObjectID",
            "Severity",
            "LastTime",
            "DSIDSigID",
            "IPSIDAlertID"], format='csv'))

        print(events.get_text(fields=[
            "msg",
            "SrcIP",
            "DstIP", 
            "SrcMac",
            "DstMac",
            "NormID",
            "HostID",
            "UserIDSrc",
            "ObjectID",
            "Severity",
            "LastTime",
            "DSIDSigID",
            "IPSIDAlertID"], format='prettytable', max_column_width=50))



