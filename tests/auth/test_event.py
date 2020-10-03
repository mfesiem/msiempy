from re import L
from unittest.case import skip
from msiempy import (
    EventManager,
    Event,
    FieldFilter,
    GroupFilter,
    AlarmManager,
    NitroSession,
    GroupedEventManager,
    GroupedEvent,
    DevTree,
)
import unittest
from datetime import datetime, timedelta

QUERY_TIMERANGE = 300


class T(unittest.TestCase):
    def test_event(self):
        events = EventManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            limit=1,
        )
        events.load_data()
        event = events[0]

        event_from_ips_get_alert_data = Event(id=event["IPSIDAlertID"])

        self.assertEqual(
            event["IPSIDAlertID"],
            "|".join(
                [
                    str(event_from_ips_get_alert_data["ipsId"]["id"]),
                    str(event_from_ips_get_alert_data["alertId"]),
                ]
            ),
        )

        if NitroSession().api_v == 2:
            print("CREATING EVENT MANUALLY FROM ID")
            data = Event().data_from_id(id=event["IPSIDAlertID"], use_query=True)
            event_from_direct_id_query = Event(data)
            print("EVENT RETREIVED : {}".format(event_from_direct_id_query))
            print("ORIGINAL EVENT : {}".format(event))
            self.assertEqual(event_from_direct_id_query, data)

    def test_query(self):

        events = EventManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            fields=Event.REGULAR_EVENT_FIELDS,
            limit=10,
        )
        events.load_data()

        for e in events:
            self.assertNotEqual(
                e["Alert.SrcIP"], "", "An event doesn't have proper source IP"
            )

        self.assertGreater(len(events), 0)

        print("EVENTS KEYS\n" + str(events.keys))
        print("EVENTS TEXT\n" + str(events))
        print("EVENT JSON\n" + events.json)

    def test_query_splitted(self):
        events_no_split = EventManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            order=(("ASCENDING", "AlertID")),
            limit=10,
        )
        events_no_split.load_data()
        print("events_no_split".upper())
        print(events_no_split.text)

        events = EventManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            order=(("ASCENDING", "AlertID")),
            limit=5,
            max_query_depth=1,  # Generate warning and ignore
        )
        events.load_data(slots=2, max_query_depth=1)  # Works
        print("events_splitted".upper())
        print(events.text)

        l1 = events_no_split[:5]
        l2 = events[:5]

        self.assertEqual(
            l1,
            l2,
            "Firts part of the splitted query doesn't correspond to the genuine query. This can happen when some event are generated at the exact same moment the query is submitted, retry the test ?",
        )

    def test_query_splitted_with_timedelta(self):
        events_no_split = EventManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            order=(("ASCENDING", "AlertID")),
            limit=10,
        )
        events_no_split.load_data()
        print("events_no_split".upper())
        print(events_no_split.text)

        events = EventManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            order=(("ASCENDING", "AlertID")),
            limit=5,
            max_query_depth=1,  # Generate warning and ignore
        )
        events.load_data(slots=2, max_query_depth=1)  # Works
        print("events_splitted".upper())
        print(events.text)

        l1 = events_no_split[:5]
        l2 = events[:5]

        self.assertEqual(
            l1,
            l2,
            "Firts part of the splitted query doesn't correspond to the genuine query. This can happen when some event are generated at the exact same moment the query is submitted, retry the test ?",
        )

    def test_filtered_query(self):

        qry_filters = [FieldFilter(name="SrcIP", values=["22.0.0.0/8"])]
        e = EventManager(fields=["SrcIP"], filters=qry_filters).load_data()
        for event in e:
            self.assertTrue(event["SrcIP"].startswith("22."))

        qry_filters = [
            GroupFilter(
                [
                    FieldFilter(name="SrcIP", values=["22.0.0.0/8"]),
                    FieldFilter("AppID", "CRON", operator="EQUALS"),
                ],
                logic="AND",
            )
        ]

        e = EventManager(fields=["SrcIP", "AppID"], filters=qry_filters).load_data()
        for event in e:
            self.assertTrue(event["SrcIP"].startswith("22."))
            self.assertEqual(event["AppID"], "CRON")

    def test_ordered_query(self):
        events_no_split = EventManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            fields=["Alert.AlertID"],
            order=(("ASCENDING", "AlertID")),
            limit=10,
        )
        events_no_split.load_data()

        last_event = None
        for event in events_no_split:
            if not last_event:
                last_event = event
                continue
            self.assertGreater(
                int(event["Alert.AlertID"]), int(last_event["Alert.AlertID"])
            )
            last_event = event

    def test_add_note(self):

        events = EventManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            limit=2,
        )
        events.load_data()

        for event in events:
            event.set_note("Test note")
            genuine_event = Event(id=event["IPSIDAlertID"])
            self.assertRegexpMatches(
                genuine_event["note"],
                "Test note",
                "The doesn't seem to have been added to the event \n" + str(event),
            )

    def test_getitem(self):
        events = EventManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            fields=Event.REGULAR_EVENT_FIELDS,
            limit=5,
        )
        events.load_data()

        print(events)

        print(
            events.get_text(
                fields=[
                    "Rule.msg",
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
                    "IPSIDAlertID",
                ],
                format="csv",
            )
        )

        print(
            events.get_text(
                fields=[
                    "Rule.msg",
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
                    "IPSIDAlertID",
                ],
                format="prettytable",
                max_column_width=50,
            )
        )

        an_event = events[1]

        print(an_event)

        self.assertTrue("Rule.msg" in an_event)
        self.assertTrue("DstIP" in an_event)
        self.assertTrue("HostID" in an_event)

        for key in [
            "Rule.msg",
            "SrcIP",
            "DstIP",
            "SrcMac",
            "DstMac",
            "NormID",
            "HostID",
        ]:
            del an_event[key]

        [
            self.assertFalse(key in an_event)
            for key in [
                "Rule.msg",
                "Alert.SrcIP",
                "Alert.DstIP",
                "Alert.SrcMac",
                "Alert.DstMac",
                "Alert.NormID",
                "Alert.BIN(4)",
            ]
        ]
        [
            self.assertFalse(key in an_event)
            for key in [
                "Rule.msg",
                "SrcIP",
                "DstIP",
                "SrcMac",
                "DstMac",
                "NormID",
                "HostID",
            ]
        ]

    def test_get_id(self):

        alarms = AlarmManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            page_size=3,
        )

        event_from_ipsGetAlertData = list(alarms.load_data())[0]["events"][0]
        event_from_notifyGetTriggeredNotificationDetail = list(
            alarms.load_data(events_details=False)
        )[0]["events"][0]
        event_from_qryGetResults = list(alarms.load_data(use_query=True))[0]["events"][
            0
        ]

        self.assertIsInstance(
            event_from_ipsGetAlertData,
            Event,
            "Event record from ipsGetAlertData has not been cast to Event object during the AlarmManager data loading",
        )
        self.assertIsInstance(
            event_from_notifyGetTriggeredNotificationDetail,
            Event,
            "Event record from notifyGetTriggeredNotificationDetail has not been cast to Event object during the AlarmManager data loading",
        )
        self.assertIsInstance(
            event_from_qryGetResults,
            Event,
            "Event record from qryGetResults has not been cast to Event object during the AlarmManager data loading",
        )

        self.assertEqual(
            event_from_ipsGetAlertData.get_id(),
            str(event_from_ipsGetAlertData["ipsId"]["id"])
            + "|"
            + str(event_from_ipsGetAlertData["alertId"]),
            "get_id() returned an ivalid ID for ipsGetAlertData type events",
        )
        self.assertEqual(
            event_from_notifyGetTriggeredNotificationDetail.get_id(),
            event_from_notifyGetTriggeredNotificationDetail["eventId"],
            "get_id() returned an ivalid ID for notifyGetTriggeredNotificationDetail type events",
        )
        self.assertEqual(
            event_from_qryGetResults.get_id(),
            event_from_qryGetResults["IPSIDAlertID"],
            "get_id() returned an ivalid ID for qryGetResults type events",
        )

        self.assertEqual(
            event_from_ipsGetAlertData.get_id(),
            event_from_notifyGetTriggeredNotificationDetail.get_id(),
            "Same events don't seem to have the same ID with get_id() method",
        )
        self.assertEqual(
            event_from_ipsGetAlertData.get_id(),
            event_from_qryGetResults.get_id(),
            "Same events don't seem to have the same ID with get_id() method",
        )

    def test_grouped_query(self):

        gevents = GroupedEventManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            field="SrcIP",
            filters=[FieldFilter("DstIP", ["127.0.0.1"], operator="IN")],
        )

        with self.assertRaisesRegex(
            ValueError, "filter must be specified when issuing a grouped query"
        ):
            gevents.load_data()

        gevents.clear_filters()
        gevents.add_filter(FieldFilter("DstIP", ["0.0.0.0/0"], operator="IN"))
        gevents.load_data()

        self.assertGreater(len(gevents), 1)
        [self.assertGreaterEqual(int(e["COUNT(*)"]), 1) for e in gevents]
        [self.assertGreaterEqual(int(e["SUM(Alert.EventCount)"]), 1) for e in gevents]
        [self.assertIsInstance(e, GroupedEvent) for e in gevents]

        for e in gevents:
            self.assertEqual(e["COUNT(*)"], e["Count"])
            self.assertEqual(e["SUM(Alert.EventCount)"], e["TotalEventCount"])
