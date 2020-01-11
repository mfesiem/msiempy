#!/usr/local/bin/python3
# Requirements : 
# - msiempy (https://github.com/mfesiem/msiempy)
# - manuf (https://github.com/coolbho3k/manuf)

"""
Usage example : ./find_dhcp_device.py -t last_hour -v Apple -m Macbook
"""

import argparse
import copy
import re
import pprint
import dateutil
import msiempy
import msiempy.event
from manuf import manuf

# DHCP log signature ID
DHCP_RENEW='272-11' #to change depending of your value

# RADIUS login log signature ID
RADIUS_START='268-2239707159' #to change depending of your value

#Key mapping for hostname and username, SIEM returns weird values... 
# Not necessary in newer version of the module
HostID='Alert.BIN(4)'
UserIDSrc='Alert.BIN(7)'

TEMPLATE_ROW=dict(user='', host='', macaddress='', seen='', ip='')

def parse_args():

    parser = argparse.ArgumentParser(description='Request logs, aggregate, and print it.')
    parser.add_argument('--time_range','-t', metavar='time_range', help='Timerange, choose from '+', '.join(msiempy.FilteredQueryList.POSSIBLE_TIME_RANGE), required=True)    
    parser.add_argument('-m', '--hostname_must_contains', metavar='Hostname match', nargs='+', default=[])
    parser.add_argument('-v', '--vendors', metavar='Vendor match', nargs='+', default=[])

    args = parser.parse_args()

    return args

def find(time_range, hostname_must_contains=[], vendors=[]):
    
    events = msiempy.event.EventManager(
        fields=[ 'HostID', 'UserIDSrc', 'SrcIP' , 'SrcMac', 'DSIDSigID' ],
        time_range=time_range,
        filters=[ msiempy.event.FieldFilter('Alert.DSIDSigID', [DHCP_RENEW, RADIUS_START]) ],
        limit=500
    )

    print('Loading data...')
    events.load_data(slots=10, workers=5, max_query_depth=2)
    print('{} events have been loaded from the SIEM'.format(len(events)))

    if len(vendors) > 0 :
        print('Filtering vendors...')
        mac = manuf.MacParser(update=True)
        vendor_filtered_events=list()

        for event in events : 

            device_vendor = mac.get_manuf(event['Alert.SrcMac'])
            if device_vendor == None:
                continue

            for vendor in vendors : 
                if vendor.lower() in device_vendor.lower() :
                    vendor_filtered_events.append(event)
                    break

        events = vendor_filtered_events
    print('{} events matches the vendor(s)'.format(len(events)))
    
    print('Aggregating events and devices...')
    devices=aggregate_list_based_on_SrcMac(events)
    print('{} unique devices in total'.format(len(devices)))

    #Apply host filters
    host_filtered_devices=list()
    for dev in devices :
        if len(hostname_must_contains)==0 or any([ match.lower() in dev.get('host').lower() for match in hostname_must_contains ]) :
            host_filtered_devices.append(dev)
    if len(devices) > len(host_filtered_devices):
        devices=host_filtered_devices
        print('{} devices matches hostname filter(s)'.format(len(devices)))

    return msiempy.NitroList(alist=devices)

def aggregate_list_based_on_SrcMac(event_list):
    new_list=list()

    nbDevicesAdded=0
    devicesUpdated=set()

    for event in event_list :
        found = False

        for entry in new_list :
           
            #if the computer was already there in the database
            if entry['macaddress'] == event['Alert.SrcMac'] :
                found=True
                
                #Updates the last seen date and IP address
                #If the event is more recent that the last seen entry date
                if dateutil.parser.parse(event['Alert.LastTime']) > dateutil.parser.parse(entry['seen']):
                    
                    entry['seen']=event['Alert.LastTime']
                    entry['ip']=event['Alert.SrcIP']

                #if the hostname is not empty, the two hostnames are not equals and the event is a dhcp event
                if (len(event[HostID])>0 and
                    entry['host'] != event[HostID] and 
                    (event['Alert.DSIDSigID'] == DHCP_RENEW)):

                    #Update the hostname
                    entry['host'] = event[HostID]
                
                #if the SIEM user field is not empty and the event is a radius login and the username is not already filled in the entry and the field is not a macaddress
                if (len(event[UserIDSrc])>0 and 
                    event['Alert.DSIDSigID'] == RADIUS_START and 
                    entry['user'] != event[UserIDSrc] and
                    re.match(r'''[0-9a-f]{2}([-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$''',event[UserIDSrc]) is None):

                    #Update the username
                    entry['user']=event[UserIDSrc]

                devicesUpdated.update([event['Alert.SrcMac']])

        if not found :
            entry=copy.copy(TEMPLATE_ROW)

            #we cannot trust the host infos from the radius events
            if event['Alert.DSIDSigID'] != RADIUS_START:
                entry['host']=event[HostID]

            #And we cannot trust the user info from the dhcp events. And sometime the user fields is a macaddress actually, so we ignore that
            elif event['Alert.DSIDSigID'] == RADIUS_START and not re.match(r'''[0-9a-f]{2}([-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$''', event[UserIDSrc]):
                entry['user']=event[UserIDSrc]

            entry['seen']= event['Alert.LastTime']
            entry['macaddress'] = event['Alert.SrcMac']
            entry['ip']=event['Alert.SrcIP']

            new_list.append(entry)

            nbDevicesAdded+=1

    print('{} devices were added'.format(nbDevicesAdded))
    print('{} devices were updated'.format(len(devicesUpdated)))
    
    return new_list


#   MAIN PROGRAM
if __name__ == "__main__":
    args = parse_args()

    devices=find(time_range=args.time_range, 
        hostname_must_contains=args.hostname_must_contains, 
        vendors=args.vendors)

    print(devices.get_text())
