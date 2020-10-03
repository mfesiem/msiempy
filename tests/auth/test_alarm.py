import msiempy
from msiempy.core import NitroList
from msiempy import EventManager
import msiempy.alarm
import unittest
import pprint
import time
from datetime import datetime, timedelta

QUERY_TIMERANGE = 300


class T(unittest.TestCase):
    def test_no_detailed_filter(self):

        alarms = msiempy.alarm.AlarmManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            page_size=5,
            status_filter="unacknowledged",
        )

        alarms.load_data()

        self.assertEqual(type(alarms), msiempy.alarm.AlarmManager, "Type error")

        self.assertEqual(
            len(alarms), 5, "Alarm list lenght differ from page_size property"
        )

        for alarm in alarms:

            self.assertEqual(type(alarm), msiempy.alarm.Alarm, "Type error")
            # self.assertEqual(type(alarm['events']), str, 'Type error')

            self.assertIn(
                alarm["acknowledgedDate"],
                ["", None],
                "status_filter is unacknowledged but alarm's acknowledgedDate has a value",
            )
            self.assertIn(
                alarm["acknowledgedUsername"],
                ["", None],
                "status_filter is unacknowledged but alarm's acknowledgedUsername has a value",
            )
            self.assertEqual(
                alarm.keys(), alarms.keys(), "Alarms's key property is wrong"
            )

        print(alarms)

    def test_alarm_filter(self):

        alarms = msiempy.alarm.AlarmManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            filters=[("severity", [80, 90])],
            page_size=10,
        )

        alarms.load_data()

        self.assertGreater(
            51,
            len(alarms),
            "The filter don't seem to have filtered any alarm from the list",
        )

        for alarm in alarms:
            self.assertEqual(type(alarm), msiempy.alarm.Alarm, "Type error")
            self.assertEqual(
                type(alarm["events"][0]), msiempy.event.Event, "Type error"
            )
            self.assertEqual(type(alarm["events"]), NitroList, "Type error")

            self.assertRegex(
                str(alarm["severity"]),
                "50|80|85|90|95|100",
                "Filtering alarms is not working",
            )

        print(alarms.json)

    def test_events_filter(self):

        alarms = msiempy.alarm.AlarmManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            filters=[("alarmName", ["Test", "IPS"])],
            event_filters=[("srcIp", ["10", "159.33", "22"])],
            page_size=10,
        )

        alarms.load_data()

        for alarm in alarms:
            self.assertEqual(type(alarm), msiempy.alarm.Alarm, "Type error")
            self.assertEqual(
                type(alarm["events"][0]), msiempy.event.Event, "Type error"
            )
            self.assertRegex(
                str(alarm["events"][0]["srcIp"]),
                "10|159.33|22",
                "Filtering alarms is not working",
            )

    def test_events_filter_using_query(self):

        alarms = msiempy.alarm.AlarmManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            filters=[("alarmName", ["Test", "IPS"])],
            event_filters=[("Alert.SrcIP", ["10", "159.33", "22"])],
            page_size=10,
        )

        print(alarms.__dict__)
        alarms.load_data(use_query=True, extra_fields=["Alert.SrcIP"])

        print(alarms.get_text(fields=["alarmName", "events"]))

        for alarm in alarms:
            self.assertEqual(type(alarm), msiempy.alarm.Alarm, "Type error")
            self.assertEqual(
                type(alarm["events"][0]), msiempy.event.Event, "Type error"
            )
            self.assertRegex(
                str(alarm["events"][0]["Alert.SrcIP"]),
                "10|159.33|22",
                "Filtering alarms is not working",
            )

    def test_print_and_compare(self):

        alarms = msiempy.alarm.AlarmManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            max_query_depth=0,
            page_size=2,
        )

        alarms_without_events_nor_details = list(alarms.load_data(alarms_details=False))
        alarms_without_events_but_with_details = list(
            alarms.load_data(events_details=False)
        )
        alarms_with_query_events = list(alarms.load_data(use_query=True))
        alarms_with_alert_data_events = list(alarms.load_data())

        """
        self.assertGreater(len(alarms_without_events),0)
   
        self.assertEqual(len(alarms_without_events), len(alarms_with_query_events), "The two lists doesn't have the same lenght")

        for i in range(len(alarms)):

            self.assertEqual(alarms_without_events[i]['alarmName'], alarms_with_query_events[i]['alarmName'], 'Loading events changed list order')

            if len(alarms_without_events[i]['events']) >0:
                event_sum=alarms_without_events[i]['events'][0]
                event_genuine=alarms_with_query_events[i]['events'][0]
                self.assertEqual(event_sum['ruleMessage'], event_genuine['Rule.msg'], 'getting event details is in trouble')
            """

        print("ALARMS WITHOUT EVENTS NOR DETAILS")
        pprint.pprint(alarms_without_events_nor_details)
        print("ALARMS WITHOUT EVENTS BUT WITH DETAILS")
        pprint.pprint(alarms_without_events_but_with_details)
        print("ALARMS WITH QUERYIED EVENTS")
        pprint.pprint(alarms_with_query_events)
        print("ALARMS WITH ALERT DATA EVENTS")
        pprint.pprint(alarms_with_alert_data_events)

    def test_paged_request_simple(self):
        alarms = msiempy.alarm.AlarmManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            page_size=10,
        )
        alarms.load_data(alarms_details=False, pages=3)

        self.assertEqual(len(alarms), 30)

        for alarm in alarms:
            self.assertEqual(type(alarm), msiempy.alarm.Alarm, "Type error")

    def test_paged_request_filtered(self):
        alarms = msiempy.alarm.AlarmManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            # filters=[('alarmName',['Test','IPS'])],
            # event_filters=[('srcIp', ['10','159.33','22'])],
            page_size=10,
        )
        alarms.load_data(pages=3)

        self.assertEqual(len(alarms), 30)

        for alarm in alarms:
            self.assertEqual(type(alarm), msiempy.alarm.Alarm, "Type error")
            self.assertEqual(
                type(alarm["events"][0]), msiempy.event.Event, "Type error"
            )
            # self.assertRegex(str(alarm['events'][0]['srcIp']), '10|159.33|22', 'Filtering alarms is not working')

    def test_loading_part_of_the_alarm_details_and_events(self):
        alarms = msiempy.alarm.AlarmManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            page_size=5,
        )
        alarms.load_data(alarms_details=False)

        for alarm in alarms:
            self.assertEqual(alarm.get("events"), None)

        detailed = alarms.perform(
            msiempy.alarm.Alarm.load_details,
            data=[alarms[1], alarms[2], alarms[3]],
            asynch=True,
            workers=3,
            progress=True,
            message="Just loading details of the first 3 alarms of the list",
        )

        for alarm in detailed:
            events = alarm.get("events", 0)  # Events should not be zero
            self.assertIn(
                type(events),
                [str, type(None), list, EventManager],
                msg="No events loaded for the alarm after load_details() call",
            )

        detailed_w_events = alarms.perform(
            msiempy.alarm.Alarm.load_events,
            data=[alarms[1]],
            message="Just loading event of the first alarm of the list",
        )

        for alarm in detailed_w_events:
            events = alarm.get("events")
            self.assertTrue(type(events[0]) == msiempy.event.Event)

        print(alarms.json)

    def test_ack_unack(self):
        alarms = msiempy.alarm.AlarmManager(
            time_range="CUSTOM",
            start_time=datetime.now() - timedelta(days=QUERY_TIMERANGE),
            end_time=datetime.now() + timedelta(days=1),
            page_size=2,
            status_filter="unacknowledged",
        )

        alarms.load_data()
        print(
            alarms.get_text(fields=["id", "acknowledgedDate", "acknowledgedUsername"])
        )
        [
            self.assertTrue(
                alarm["acknowledgedDate"] == None,
                msg="acknowledgedDate is not None for an unacknowledged alarm, it's {}".format(
                    alarm["acknowledgedDate"]
                ),
            )
            for alarm in alarms
        ]

        # alarms.nitro._init_log(verbose=True)

        alarms.perform(msiempy.alarm.Alarm.acknowledge)
        time.sleep(3)
        alarms.perform(msiempy.alarm.Alarm.refresh)

        # while len(alarms[0]['acknowledgedDate']) == 0 :
        #     print(alarms.get_text(fields=['id','acknowledgedDate','acknowledgedUsername']))
        #     alarms.perform(msiempy.alarm.Alarm.acknowledge)
        #     time.sleep(15)
        #     alarms.nitro.logout()
        #     alarms.nitro.login()
        #     alarms.perform(msiempy.alarm.Alarm.refresh)
        #     alarms.perform(msiempy.alarm.Alarm.refresh)

        print(
            alarms.get_text(fields=["id", "acknowledgedDate", "acknowledgedUsername"])
        )
        [self.assertTrue(len(alarm["acknowledgedDate"]) > 0) for alarm in alarms]

        alarms.perform(msiempy.alarm.Alarm.unacknowledge)
        time.sleep(3)
        alarms.perform(msiempy.alarm.Alarm.refresh)

        # while len(alarms[0]['acknowledgedDate']) > 0 :
        #     print(alarms.get_text(fields=['id','acknowledgedDate','acknowledgedUsername']))
        #     alarms.perform(msiempy.alarm.Alarm.unacknowledge)
        #     time.sleep(15)
        #     alarms.nitro.logout()
        #     alarms.nitro.login()
        #     alarms.perform(msiempy.alarm.Alarm.refresh)
        # alarms.perform(msiempy.alarm.Alarm.refresh)

        print(
            alarms.get_text(fields=["id", "acknowledgedDate", "acknowledgedUsername"])
        )
        [self.assertTrue(alarm["acknowledgedDate"] == None) for alarm in alarms]
