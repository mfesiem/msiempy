"""
Quick python code to list all McAfee SIEM Datasources
"""

import pandas
from msiempy.device import DevTree

devtree = DevTree()
print("All Datasources")
print(devtree.get_text(fields=["parent_name", "name", "ds_id"]))

df = pandas.DataFrame(devtree)
print("Datasources grouped by parent")
print(
    df.groupby("parent_name")["name"]
    .apply(lambda x: ", ".join(x))
    .reset_index()
    .to_string(index=False)
)
