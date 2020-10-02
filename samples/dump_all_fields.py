from msiempy import NitroSession
import pprint

session = NitroSession()
filters = session.request("get_possible_filters")
fields = session.request("get_possible_fields", type="EVENT", groupType="NO_GROUP")
print()
print()
print("FIELDS NAMES S:\n{}".format(pprint.pformat(fields)))
print()
print()
print("FIELDS NAMES YOU CAN USE IN FILTERS:\n{}".format(pprint.pformat(filters)))
print()
print()
print("FIELDS NAMES SUMMARY:\n{}".format([field["name"] for field in fields]))
print()
print()
print(
    "FIELDS NAMES YOU CAN USE IN FILTERS SUMMARY:\n{}".format(
        [field["name"] for field in filters]
    )
)
