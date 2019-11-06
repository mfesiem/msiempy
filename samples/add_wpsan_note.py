#!/usr/local/bin/python3
#Requirement :  msiempy (https://github.com/mfesiem/msiempy)

"""
Usage example : ./add_wpsan_note.py -t last_24_hours
"""

import argparse
import subprocess
import re
import msiempy
from msiempy.alarm import AlarmManager, Alarm
from msiempy import NitroConfig

#Wpscan path, to adapt depending your env. 
#   Could be '/usr/local/rvm/gems/ruby-2.6.0/bin/wpscan'
#   or "env GEM_HOME=/usr/local/rvm/gems/ruby-2.6.0@wpscanv3 /usr/local/rvm/rubies/ruby-2.6.0/bin/ruby /home/user/tools/wpscan/bin/wpscan" 
WPSCAN = "wpscan"

def parse_args():

    parser = argparse.ArgumentParser(description='Add wpscan result as a note to Wordpress events that triggered an alarm. It currently only uses the destination IP as the url.')
    parser.add_argument('--time_range','-t', metavar='time_range', help='Timerange, choose from '+', '.join(msiempy.FilteredQueryList.POSSIBLE_TIME_RANGE), required=True)
    args = parser.parse_args()

    return args

def add_wpscan_note(alarm):
    if len(alarm['events'])>0:

        #Parsing host from description field
        description = None
        for field in alarm['events'][0].get('customTypes'):
            if field.get("fieldName") == "Description":
                description=field.get("formatedValue")

        matches = re.findall('(?<=HTTP Host ==  ).+?(?=;;;)', description)
        host = matches[0] if len(matches) > 0 else alarm['events'][0].get('destIp')

        try :
            cmd = [WPSCAN, #Arguments for Version 3.7.4
                '--no-banner', 
                '--random-user-agent', 
                '--format', 'cli-no-colour',
                '--detection-mode', 'aggressive',
                '--disable-tls-checks',
                '--force',
                '--enumerate', 'vp,vt,cb,dbe,u,m',
                '--url', str(host)]

            print('Running command : {}'.format(' '.join(cmd)))

            wpscan_result = subprocess.check_output(cmd)

        except subprocess.CalledProcessError as err :
            wpscan_result = err.output

        finally:
            note = str(wpscan_result.decode('utf-8'))

            print('Adding note :\n\t{}\nTo alarm\'s triggering event : \n\t{} triggered at {} by {} event regarding host {}'.format(
                note, alarm['alarmName'], alarm['triggeredDate'], alarm['events'][0]['ruleName'], host))

            alarm['events'][0].set_note(note)


#   MAIN PROGRAM
if __name__ == "__main__":
    args=parse_args()

    wordpress_alarms = AlarmManager(
        status_filter='unacknowledged',
        time_range=args.time_range,
        page_size=400,
        filters=[('severity','80')],
        event_filters=[('ruleName',['WordPress'])]
    )

    wordpress_alarms.load_data(pages=3)

    updated = subprocess.check_output([WPSCAN,'--update'])

    if 'Update completed' in str(updated) :
        wordpress_alarms.perform(func=add_wpscan_note)
    else:
        raise Exception('Wordpress update failed ! Quitting script.')

