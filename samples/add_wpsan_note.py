#!/usr/local/bin/python3
#Requirement :  msiempy (https://github.com/mfesiem/msiempy)

import argparse
import subprocess
from msiempy.alarm import AlarmManager, Alarm
from msiempy import NitroConfig

WPSCAN = "env GEM_HOME=/usr/local/rvm/gems/ruby-2.6.0@wpscanv3 /usr/local/rvm/rubies/ruby-2.6.0/bin/ruby /home/script-server/tools/wpscan/bin/wpscan"#'/usr/local/rvm/gems/ruby-2.6.0/bin/wpscan'

def parse_args():

    parser = argparse.ArgumentParser(description='Add wpscan result as a note to Wordpress events that triggered an alarm.')
    parser.add_argument('-t', '--timerange', metavar='Time range', help='SIEM time range to analyse. For example LAST_3_DAYS.', required=True)

    args = parser.parse_args()

    return args

def add_wpscan_note(alarm):
    if len(alarm['events'])>0:
        try :
            wpscan_result = subprocess.check_output(
                [WPSCAN, 
                '--no-banner', 
                '--random-user-agent', 
                '--format', 'cli-no-colour',
                '--detection-mode', 'aggressive',
                '--disable-tls-checks',
                '--force',
                '--enumerate', 'vp,vt,cb,dbe,u,m',
                '--url', str(alarm['events'][0]['Alert.DstIP'])])

        except subprocess.CalledProcessError as err :
            wpscan_result = err.output

        finally:
            note = str(wpscan_result.decode('utf-8'))
            print('Adding note :\n{}\nto alarm event :\n{}'.format(note, alarm))
            alarm['events'][0].add_note(note)


#   MAIN PROGRAM
if __name__ == "__main__":
    args=parse_args()

    print(NitroConfig())

    wordpress_alarms = AlarmManager(
        time_range=args.timerange,
        page_size=500,
        filters=[('ruleMessage','Wordpress')]
    )

    wordpress_alarms.load_data()
    wordpress_alarms.load_events(extra_fields=['URL', 'Description'])

    updated = subprocess.check_output([WPSCAN,'--update'])

    if 'Update completed' in str(updated) :
        wordpress_alarms.perform(func=add_wpscan_note, progress=True)
    else:
        raise Exception('Wordpress update failed ! Quitting script.')

