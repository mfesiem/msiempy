### Samples

*Not all samples are listed in this readme!*

#### A few quick examples

Onpen the file `examples.py` and look it up :). 

#### Acknowledge irrelevants 404 or errored alarms

See: https://github.com/mfesiem/ack-irrelevants-ips-alarms

#### Add wpsan result as note to event that trigerred Wordpress alarms

```bash
$ python3 ./add_wpsan_note.py -h 
usage: add_wpsan_note.py [-h] --time_range time_range

Add wpscan result as a note to Wordpress events that triggered an alarm. It
currently only uses the destination IP as the url.

optional arguments:
  -h, --help            show this help message and exit
  --time_range time_range, -t time_range
                        Timerange, choose from CUSTOM, LAST_MINUTE,
                        LAST_10_MINUTES, LAST_30_MINUTES, LAST_HOUR,
                        CURRENT_DAY, PREVIOUS_DAY , LAST_24_HOURS, LAST_2_DAYS,
                        LAST_3_DAYS, CURRENT_WEEK, PREVIOUS_WEEK,
                        CURRENT_MONTH, PREVIOUS_MONTH, CURRENT_QUARTER,
                        PREVIOUS_QUARTER, CURRENT_YEAR, PREVIOUS_YEAR
```

#### Find a devices based DHCP logs (or others), macaddress vendor and hostname

```bash
% python3 ./find_dhcp_device.py -h            
usage: find_dhcp_device.py [-h] --time_range time_range
                           [-m Hostname match [Hostname match ...]]
                           [-v Vendor match [Vendor match ...]]

Request logs, aggregate, and print it.

optional arguments:
  -h, --help            show this help message and exit
  --time_range time_range, -t time_range
                        Timerange, choose from CUSTOM, LAST_MINUTE,
                        LAST_10_MINUTES, LAST_30_MINUTES, LAST_HOUR,
                        CURRENT_DAY, PREVIOUS_DAY, LAST_24_HOURS, LAST_2_DAYS,
                        LAST_3_DAYS, CURRENT_WEEK, PREVIOUS_WEEK,
                        CURRENT_MONTH, PREVIOUS_MONTH, CURRENT_QUARTER,
                        PREVIOUS_QUARTER, CURRENT_YEAR, PREVIOUS_YEAR
  -m Hostname match [Hostname match ...], --hostname_must_contains Hostname match [Hostname match ...]
  -v Vendor match [Vendor match ...], --vendors Vendor match [Vendor match ...]
  
```
