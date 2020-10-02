import unittest
import pytest
from msiempy.core import NitroList
import csv
import time
import json
import requests


def get_testing_data(data="./tests/local/test-events.json"):
    return json.load(open(data, "r"))


class T(unittest.TestCase):

    manager = NitroList(alist=get_testing_data())

    def test_json(self):

        json_dump = T.manager.json
        try:
            loaded = json.loads(json_dump)
            self.assertEqual(
                len(T.manager),
                len(loaded),
                "Json dump doesn't have the same lengh as manger object",
            )
            for i in range(len(loaded)):
                self.assertEqual(
                    dict(T.manager[i]),
                    loaded[i],
                    "Json dump doesn't present the same info in the same order",
                )
        except Exception as e:
            self.fail("Can't load json object :" + str(e))

    def test_manager(self):
        manager = NitroList(alist=get_testing_data())

        sublist = manager.search("Postfix Disconnect from host", fields="Rule.msg")
        print(sublist[:4])
        sublist_1 = manager.search("Postfix Disconnect from host")

        for i in sublist:
            self.assertIn("Postfix Disconnect from host", i["Rule.msg"])
            self.assertIn(i, sublist_1)

        sublist2 = manager.search(
            "Postfix Disconnect from host", fields="Rule.msg", invert=True
        )
        sublist2_1 = manager.search("Postfix Disconnect from host", invert=True)
        for i in sublist2:
            self.assertNotIn("Postfix Disconnect from host", i["Rule.msg"])
            self.assertIn(i, sublist2_1)

        sublist3 = manager.search("Postfix|cron", fields="Rule.msg")
        for i in sublist3:
            self.assertTrue("Postfix" in i["Rule.msg"] or "cron" in i["Rule.msg"])

        sublist4 = manager.search("Postfix", "Connect", fields="Rule.msg")
        for i in sublist4:
            self.assertTrue("Postfix" in i["Rule.msg"] and "Connect" in i["Rule.msg"])

    def test_print(self):
        data = get_testing_data()
        manager = NitroList(alist=data[:30])
        # Messing arround with the list
        manager[10]["Rule.msg"] = NitroList(alist=data[:5])
        manager[20]["Rule.msg"] = data[:5]

        print("CSV")
        print(manager.get_text(format="csv"))

        print("NORMAL")
        print(manager.text)

        print("SPECIFIC FIELDS")
        print(manager.get_text(fields=["Rule.msg", "Alert.LastTime"]))
