"""
Print raw events results hour by hour for the past 24h
"""

from datetime import datetime

from msiempy.event import EventManager
from msiempy.__utils__ import parse_timedelta, divide_times

# Generate last 24h tuples (start_time, end_time)
periods = divide_times(
    first=datetime.now() - parse_timedelta("24h"), last=datetime.now(), slots=24
)

periods_results = list()

for time in periods:

    query = EventManager(
        start_time=time[0],
        end_time=time[1],
        filters=[("SrcIP", ["22.0.0.0/8", "127.0.0.1"])],
    )

    query.load_data()
    periods_results.append(query)

for i, p in enumerate(periods_results):
    print("{} hours ago, query got {}".format(24 - i, periods_results[i]))
