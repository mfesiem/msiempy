import unittest
import pprint
from msiempy.event import Event, EventManager


class T(unittest.TestCase):

    TEST_EVENTS = [
        {
            "Alert.DSIDSigID": "49190-4294967295",
            "Alert.DstIP": "139.1.1.4",
            "Alert.DstMac": "00:00:00:00:00:00",
            "Alert.DstPort": "port/code:0",
            "Alert.IPSIDAlertID": "144116287688146944|23585723",
            "Alert.LastTime": "10/03/2019 11:52:22",
            "Alert.SrcIP": "22.22.24.22",
            "Alert.SrcMac": "00:00:00:00:00:00",
            "Alert.SrcPort": "port/type:0",
            "Rule.NormID": "4026531840",
            "Rule.msg": "unknown event",
        },
        {
            "Alert.DSIDSigID": "49190-429967295",
            "Alert.DstIP": "139.55.124.9",
            "Alert.DstMac": "00:00:00:00:00:00",
            "Alert.DstPort": "port/code:0",
            "Alert.IPSIDAlertID": "144116287654592512|23585609",
            "Alert.LastTime": "10/03/2019 11:52:58",
            "Alert.SrcIP": "22.22.24.4",
            "Alert.SrcMac": "00:00:00:00:00:00",
            "Alert.SrcPort": "port/type:0",
            "Rule.NormID": "4026531840",
            "Rule.msg": "unknown event",
        },
    ]

    def test_sinlge(self):
        event = Event(adict=T.TEST_EVENTS[0])
        print("get SrcIP, DstIP, LastTime")
        print(
            event.get("SrcIP")
            + ", "
            + event.get("DstIP")
            + ", "
            + event.get("LastTime")
        )

    def test_manager(self):
        events = EventManager(alist=T.TEST_EVENTS)
        print("get_text(fields=['SrcIP', 'DstIP', 'LastTime'])")
        print(events.get_text(fields=["SrcIP", "DstIP", "LastTime"]))

    def test_unique_keys(self):

        ukeys = EventManager(
            fields=[
                "Rule.msg",
                "Alert.SrcIP",
                "Alert.DstIP",
                "Alert.IPSIDAlertID",
                "Alert.LastTime",
                "SrcMac",
                "Alert.SrcMac",
                "Alert.DstMac",
                "Alert.NormID",
                "Alert.BIN(4)",
                "HostID",
                "Alert.BIN(7)",
                "DSID",
                "Alert.EventCount",
            ]
        ).fields
        print("Got")
        print(sorted(ukeys))
        print("EXPECTED")
        print(
            sorted(
                [
                    "Alert.NormID",
                    "DSID",
                    "DstIP",
                    "DstMac",
                    "EventCount",
                    "HostID",
                    "IPSIDAlertID",
                    "LastTime",
                    "Rule.msg",
                    "SrcIP",
                    "SrcMac",
                    "UserIDSrc",
                ]
            )
        )

        self.assertEqual(
            sorted(ukeys),
            sorted(
                [
                    "Alert.NormID",
                    "DSID",
                    "DstIP",
                    "DstMac",
                    "EventCount",
                    "HostID",
                    "IPSIDAlertID",
                    "LastTime",
                    "Rule.msg",
                    "SrcIP",
                    "SrcMac",
                    "UserIDSrc",
                ]
            ),
        )
