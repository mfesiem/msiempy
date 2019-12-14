### Samples

#### A few quick examples

`python3 ./examples.py`
#### Acknowledge irrelevants 404 or errored alarms
```bash
$ python3 ./ack_irrelevants.py -h
usage: ack_irrelevants.py [-h] --time_range time_range [--start_time time]
                          [--end_time time] [--page_size page_size]
                          [--response_codes response codes]
                          [--resources resources] [--force]

Acknowledge irrelevants IPS - High Severity Event alarms

optional arguments:
  -h, --help            show this help message and exit
  --time_range time_range, -t time_range
                        Timerange, choose from CUSTOM, LAST_MINUTE,
                        LAST_10_MINUTES, LAST_30_MINUTES, LAST_HOUR,
                        CURRENT_DAY, PREVIOUS_DAY, LAST_24_HOURS, LAST_2_DAYS,
                        LAST_3_DAYS, CURRENT_WEEK, PREVIOUS_WEEK,
                        CURRENT_MONTH, PREVIOUS_MONTH, CURRENT_QUARTER,
                        PREVIOUS_QUARTER, CURRENT_YEAR, PREVIOUS_YEAR
  --start_time time, --t1 time
                        Start trigger date
  --end_time time, --t2 time
                        End trigger date
  --page_size page_size, -p page_size
                        Size of alarms list
  --response_codes response codes, -r response codes
                        List of response codes to acknowledge. Commas
                        separated values. Example : "403,404". Use "error" to
                        include network errored requests.
  --resources resources, -s resources
                        List of string matches url resources to acknowledge.
                        Acknowledge any resources if not specified. Commas
                        separated values. Example :
                        "setup.cgi,login.cgi,user.php"
  --force               Will not prompt for confirmation before acknowledging
                        alarms
```
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
