"""Provide ESM, ERC and data source management.
"""

import logging
log = logging.getLogger('msiempy')

import csv
import ipaddress
import inspect
import json
import logging
import re
import sys
from itertools import chain
from io import StringIO
from functools import partial, lru_cache

from . import NitroDict, NitroList, NitroError, NitroObject
from .__utils__ import dehexify

class Device(NitroObject):
    pass

class ERC(Device):
    pass

class ESM(Device):
    """
    ESM class
    
    Puvlic Methods:
    
        version()       Returns simple version string, '10.1.0'
        
        buildstamp()    Returns buildstamp string, '10.0.2 20170516001031'
        
        time()          Returns ESM time (GMT)
        
        disks()         Returns string of disk status
        
        ram()           Returns string of disk status
        
        backup_status()     Returns dict with keys:
                             - autoBackupEnabled: bool
                             - autoBackupDay: int
                             - backupLastTime: str (timestamp)
                             - backupNextTime: str (timestamp)
        
        callhome()      Returns True/False if callhome is active/not active
        
        rulestatus()    Returns dict with keys:
                        - rulesAndSoftwareCheckEnabled: bool
                        - rulesAndSoftLastCheck: str (timestamp)
                        - rulesAndSoftNextCheck: str (timestamp)

        status()        Returns dict with the status outputs above plus a few
                        other less interesting details.
               
        timezones()     Returns dict (str, str)
                            timezone_id: timezone_name
        
        tz_name_to_id(id)         Returns timezone name matching given timezone ID.
        
        tz_id_to_name(tz_name)    Returns timezone ID matching given timezone name.
        
        tz_offsets()    Returns list of timezone tuples. 
                        (tz_id, tz_name, tz_offset)
                        [(1, 'Midway Island, Samoa', '-11:00'),
                         (2, 'Hawaii', '-10:00'),
            
        type_id_to_venmod(type_id)     Returns tuple. (vendor, model) matching
                                       provided type_id.
        
        venmod_to_type_id(vendor, model)    Returns string of matching type_id
        
    """
    def __init__(self, *args, **kwargs):
        """
        Returns:
            obj. ESM object
        """
        super().__init__(*args, **kwargs)
        
    def refresh(self):
        super().refresh()

    @property
    def text(self):
        return str('ESM object')

    @property
    def json(self):
        return (dict(self))

    def time(self):
        """
        Returns:
            str. ESM time (GMT).

        Example:
            '2017-07-06T12:21:59.0+0000'
        """
        return self.nitro.request("get_esm_time")['value']

    def buildstamp(self):
        return self.nitro.buildstamp
    
    def version(self):
        return self.nitro.version

    def status(self):
        """
        Returns:
            dict. ESM stats.
            including:
                - processor status
                - hdd status
                - ram status
                - rule update status
                - backup status
                - list of top level devices
        Other functions exist to return subsets of this data also.
        """
        status = self.nitro.request("get_sys_info")
        return self.map_status_int_fields(status)

    def map_status_int_fields(self, status):
        new_status = {}
        new_status['cpu'] = status['HDW'].split('\n')[0][6:]
        new_status['hdd'] = status['HDW'].split('\n')[1][6:]
        new_status['ram'] = status['HDW'].split('\n')[2][6:]
        new_status['autoBackupEnabled'] = status['ABENABLED']
        new_status['autoBackupHour'] = status['ABHOUR']
        new_status['autoBackupDay'] = status['ABDAY']
        new_status['backupNextTime'] = status['BUNEXT']
        new_status['backupLastTime'] = status['BULAST']
        new_status['rulesAndSoftwareCheckEnabled'] = status['RSCENABLED']
        new_status['rulesAndSoftNextCheck'] = status['RSNEXT']
        if status['RSLAST'] == 'RSLAST':
            new_status['rulesAndSoftLastCheck'] = None
        else:
            new_status['rulesAndSoftLastCheck'] = status['RSLAST']
        if status['CHIP'] == 'CHIP':
            new_status['callHomeIp'] = None
        else:
            new_status['callHomeIp'] = status['CHIP']
        return new_status


    def disks(self):
        """
        Returns:
            str. ESM disks and utilization.

        Example:
            'sda3     Size:  491GB, Used:   55GB(12%), Available:  413GB, Mount: /'
        """
        return self.status()['hdd']

    def ram(self):
        """
        Returns:
            str. ESM ram and utilization.

        Example:
            'Avail: 7977MB, Used: 7857MB, Free: 119MB'
        """
        return self.status()['ram']

    def backup_status(self):
        """
        Returns:
            dict. Backup status and timestamps.

            {'autoBackupEnabled': True,
                'autoBackupDay': 7,
                'autoBackupHour': 0,
                'backupLastTime': '07/03/2017 08:59:36',
                'backupNextTime': '07/10/2017 08:59'}
        """
        fields = ['autoBackupEnabled',
                   'autoBackupDay',
                   'autoBackupHour',
                   'autoBackupHour',
                   'backupNextTime']

        return {key: val for key, val in self.status().items()
                if key in fields}

    def callhome(self):
        """
        Returns:
            bool. True/False if there is currently a callhome connection
        """
        if self.status()['callHomeIp']:
            return True

    def rules_status(self):
        """
        Returns:
            dict. Rules autocheck status and timestamps.

        Example:
        { 'rulesAndSoftwareCheckEnabled': True
          'rulesAndSoftLastCheck': '07/06/2017 10:28:43',
          'rulesAndSoftNextCheck': '07/06/2017 22:28:43',}

        """
        self._fields = ['rulesAndSoftwareCheckEnabled',
                        'rulesAndSoftLastCheck',
                        'rulesAndSoftNextCheck']
        return {self.key: self.val for self.key, self.val in self.status().items()
                if self.key in self._fields}

    @lru_cache(maxsize=None)    
    def recs(self):
        """
        Returns: 
            
        """
        rec_list = self.nitro.request('get_recs')
        return [(rec['name'], rec['id']['id'])for rec in rec_list]
                
    @lru_cache(maxsize=None)   
    def _get_timezones(self):
        """
        Gets list of timezones from the ESM.
        
        Returns:
            str. Raw return string from ESM including 
        """
        return self.nitro.request('time_zones')
        
    def tz_offsets(self):
        """
        Builds table of ESM timezones including offsets.
        
        Returns:
            list. List of timezone tuples (name, id, offset)
            
        Example:
            [(1, 'Midway Island, Samoa', '-11:00'),
             (2, 'Hawaii', '-10:00'),
             ...
            ]
        """
        return [(tz['id']['value'], tz['name'], tz['offset']) 
                  for tz in self._get_timezones()]
                   
        
    def timezones(self):
        """
        Builds table of ESM timezones and names only. No offsets.
        
        Returns:
            dict. {timezone_id, timezone_name}
        """
        return {str(tz['id']['value']): tz['name']
                            for tz in self._get_timezones()}

    def tz_name_to_id(self, tz_name):
        """
        Args:
            tz_name (str): Case sensitive, exact match timezone name
            
        Returns:
            str. Timezone id or None if there is no match
        """
        tz_reverse = {tz_name.lower(): tz_id 
                        for tz_id, tz_name in self.timezones().items()}
        try:
            return tz_reverse[tz_name.lower()]
        except KeyError:
            return None
    
    def tz_id_to_name(self, tz_id):
        """
        Args:
            td_id (str): Numerical string (Currently 1-74)
        
        Returns:
            str. Timezone name or None if there is no match
        """
        try:
            return self.timezones()[tz_id]
        except KeyError:
            return None
    
    def type_id_to_venmod(self, type_id):
        """
        Args:
            type_id (str): Numerical string 
        
        Returns:
            tuple. (vendor, model) or None if there is no match
        """
        ds_types = self._get_ds_types()
        for venmod in ds_types:
            if str(venmod[0]) == str(type_id):
                return (venmod[1], venmod[2])
        return(('Unkown vendor for type_id {}'.format(type_id),'Unkown vendor'))

    def venmod_to_type_id(self, vendor, model):
        """
        Args:
            vendor (str): Exact vendor string including puncuation
            model (str): Exact vendor string including puncuation
        
        Returns:
            str. Matching type_id or None if there is no match
        """
        for venmod in self._get_ds_types():
            if vendor == venmod[1]:
                if model == venmod[2]:
                    return str(venmod[0])

    def rules_history(self):
        """
        Returns: 
            Policy Editor rule history.
        """
        file = self.nitro.request('get_rule_history')['TK']

        pos = 0
        nbytes = 0
        resp = self.nitro.request('get_rfile2', ftoken=file, pos=pos, nbytes=nbytes)


        if resp['FSIZE'] == resp['BREAD']:
            data = resp['DATA']
            #data = resp['DATA'].split('\n')
            self.nitro.request('del_rfile', ftoken=file)
            return data
        
        data = []
        data.append(resp['DATA'])
        file_size = int(resp['FSIZE'])
        collected = int(resp['BREAD'])

        while file_size > collected:
            pos += int(resp['BREAD'])
            nbytes = file_size - collected
            resp = self.nitro.request('get_rfile2', ftoken=file, pos=pos, nbytes=nbytes)
            collected += int(resp['BREAD'])
            data.append(resp['DATA'])

        resp = self.nitro.request('del_rfile', ftoken=file)
        return ''.join(data)

    def _format_rules_history(self, rules_history):
        """[summary]
        
        Arguments:
            rules_history {[type]} -- [description]
        """

    @lru_cache(maxsize=None)   
    def _get_ds_types(self):
        """
        Retrieves device table from ESM
                    
        Returns:
            list. of tuples output from callback: _format_ds_types()

        Note:
            rec_id (str): self.rec_id assigned in method
        """
        rec_id = self.recs()[0][1]
        return  self.nitro.request('get_dstypes', rec_id=rec_id)
                    
    def _format_ds_types(self, venmods):
        """
        Callback to create type_id/vendor/model table
        
        Args:
            venmods (obj): request object from _get_ds_types
        
        Returns:
            list. of tuples 
                
           [(542, 'McAfee', 'SaaS Email Protection')
            (326, 'McAfee', 'Web Gateway')
            (406, 'Microsoft', 'ACS - SQL Pull')
            (491, 'Microsoft', 'Endpoint Protection - SQL Pull')
            (348, 'Microsoft', 'Exchange')]

        Note: 
            This is a callback for _get_ds_types.

        """
        return [(mod['id']['id'], ven['name'], mod['name'],)
                    for ven in venmods['vendors']
                    for mod in ven['models']]

class DevTree(NitroList):
    """
    Interface to the ESM device tree.
    
    Public Methods:
    
        search('term')      Returns a DataSource object matching the name,
                        IPv4/IPv6 address, hostname or device ID.

        search_group(field='term')    Returns a list of DataSource objects that match 
                                  the given term for the given field. 
                                  Valid field options include:
                                    - parent_id = '144119615532826624'
                                    - type_id = '65'
                                    - vendor = 'Intersect Alliance'
                                    - model = 'Snare for Windows'
                                    - syslog_tls = 'T'
                                    - port = '514'
                                    - tz_id = '51'
                                    - tz_name = 'Darwin'
                                    - zone_id = '7'
                                    
        steptree()  Returns an ordered list of lists representing the 
                       default 'Physical Display' device tree on the ESM.
                       This is useful to recreate a graphical representation
                       of the device tree.
                    
                       Inner list fields: [tree_id, ds_name, ds_ip, depth]

                       tree_id: The order in which the datasource 
                                 appears in the ESM 'Physical Display'
                                 
                       name:   Datasource name
                        
                       IP:     Datasource IP
                        
                       depth:  1 = ESM
                                2 = ERC/ADM/DEM/ACE/ELM/ELS
                                3 = Datasources including EPO/NSM
                                4 = Children and Clients
                        
        last_times(days=,       Returns a list of DataSource objects that 
                   hours=,      the ESM has NOT heard from since the
                   minutes=)    provided timeframe.
                                  args are cummulative, 
                               e.g. (days=30, hours=5) will added together


        refresh()   Rebuilds the tree
                            
        __len__     Returns the total number of devices in the tree
        
        __iter__    Interates through each DataSource object in the tree. 
        
        __contains__    Returns bool as to whether a datasource name, IP,
                        hostname or ds_id exist in the device tree.
                        
    """
    _DevTree = []

    def __init__(self, *args, **kwargs):
        """
        Initalize the DevTree object
        """
        super().__init__(*args, **kwargs)
        self.devtree = self.build_devtree()

    def __len__(self):
        """
        Returns the count of devices in the device tree.
        """
        return len(self.devtree)
        
    def __iter__(self):
        """
        Returns:
            Generator with datasource objects.
        """
        for ds in self.devtree:
            yield ds

    def __str__(self):
        return json.dumps(self.devtree)


    def __repr__(self):
        return json.dumps(self.devtree)

    def __contains__(self, term):
        """
        Returns:
            bool: True/False the name or IP matches the provided search term.
        """
        if self.search(term):
            return True
        else:
            return None
            
    def search(self, term, rec_id=None, zone_id='0'):
        """
        Args:
            term (str): Datasource name, IP, hostname or ds_id
            
            zone_id (int): Provide zone_id to limit search to a specific zone

        Returns:
            Datasource object that matches the provided search term or None.

        """
        search_fields = ['ds_ip', 'name', 'hostname', 'ds_id']

        found = [ds for ds in self.devtree
                    for field in search_fields 
                    if ds[field].lower() == term.lower()
                    if ds['zone_id'] == zone_id]

        if rec_id and found:
            found = [ds for ds in found 
                        if ds['parent_id'] == rec_id]
        
        if found:
            return DataSource(**found[0])
        else:
            return None

    def search_ds_group(self, field, term, zone_id='0'):
        """
        Args:
            field (str): Valid DS config field to search
            term (str): Data to search for in specified field
            
        Returns:
            Generator containing any matching DataSource objects or None
            Result must be iterated through.
            
        Raises:
            ValueError: if field or term are None
        """
        return (DataSource(adict=ds) for ds in self.devtree
                        if ds.get(field) == term)
                       
    def steptree(self):
        """
        Summarizes the devtree into names and IPs. 
        
        Includes depth count to indicate how many steps from the root 
        of the tree the device would be if this data were presented 
        graphically. 
        
        Also includes parent_id as another method to group datasources 
        under another device.
        
        Returns:
            List of tuples (int,str,str,str) (step, name, ip, parent_id)        
        """
        self._steptree = []
        _ones = ['14']
        _twos = ['2', '4', '10', '12', '15', '25']
        _threes = ['3', '5', '7', '17', '19', '20', '21', '24', '254']
        _fours = ['7','17', '23', '256']

        for ds in self.devtree:
            if ds['desc_id'] in _ones:
                ds['depth'] = '1'
            elif ds['desc_id'] in _twos:
                ds['depth'] = '2'
            elif ds['desc_id'] in _threes:
                ds['depth'] = '3'
            else:
                ds['depth'] = '4'
            self._steptree.append((ds['idx'], ds['name'], 
                                    ds['ds_ip'], ds['depth'],))
        return self._steptree

                    
    def refresh(self):
        """
        Rebuilds the devtree
        """
        self.build_devtree()
        
    def get_ds_times(self):
        """
        """
        last_times = self._get_last_event_times()
        self._insert_ds_last_times()
        return last_times
        
    def recs(self):
        """
        Returns:
            list of Receiver dicts (str:str)
        """
        return [self._rec for self._rec in self.devtree
                    if self._rec['desc_id'] == '2']
    
    def build_devtree(self):
        """
        Coordinates assembly of the devtree object
        """
        devtree = self._get_devtree()        
        devtree = self._format_devtree(devtree)
        devtree = self._insert_rec_info(devtree)        
        containers = self._get_client_containers(devtree)
        devtree = self._merge_clients(containers, devtree)
        zonetree = self._get_zonetree()
        devtree = self._insert_zone_names(zonetree, devtree)
        zone_map = self._get_zone_map()
        devtree = self._insert_zone_ids(zone_map, devtree)            
        last_times = self._get_last_times()
        last_times = self._format_times(last_times)
        devtree = self._insert_ds_last_times(last_times, devtree)
        devtree = self._filter_bogus_ds(devtree)
        return devtree

    def _get_devtree(self):
        """
        Returns:
            ESM device tree; raw, but ordered, string.
            Does not include client datasources.
        """
        resp = self.nitro.request('get_devtree')
        return dehexify(resp['ITEMS'])

    def _format_devtree(self, devtree):
        """
        Parse key fields from raw device strings into datasource dicts

        Returns:
            List of datasource dicts
        """
        devtree = StringIO(devtree)
        devtree = csv.reader(devtree, delimiter=',')
        devtree_lod = []
        _ignore_remote_ds = False

        for idx, row in enumerate(devtree, start=1):
            if len(row) == 0:
                continue

            # Get rid of duplicate 'asset' devices
            if row[0] == '16':  
                continue

            # Filter out distributed ESMs                
            if row[0] == '9':  
                _ignore_remote_ds = True
                continue
            
            # Filter out distributed ESM data sources
            if _ignore_remote_ds:  
                if row[0] != '14':
                    continue
                else:
                    _ignore_remote_ds = False
            
            if row[2] == "3":  # Client group datasource group containers
                row.pop(0)     # are fake datasources that seemingly have
                row.pop(0)     # two uneeded fields at the beginning.
            if row[16] == 'TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT':
                row[16] = '0'  # Get rid of weird type-id for N/A devices
            
            if len(row) < 29:
                #print('Unknown datasource: {}.'.format(self._row))
                continue
            
            ds_fields = {'idx': idx,
                            'desc_id': row[0],
                            'name': row[1],
                            'ds_id': row[2],
                            'enabled': row[15],
                            'ds_ip': row[27],
                            'hostname': row[28],
                            'type_id': row[16],
                            'vendor': '',
                            'model': '',
                            'tz_id': '',
                            'date_order': '',
                            'port': '',
                            'syslog_tls': '',
                            'client_groups': row[29],
                            'zone_name': '',
                            'zone_id': '',
                            'client': False
                            }
            devtree_lod.append(ds_fields)
        return devtree_lod

    def _insert_rec_info(self, devtree):
        """
        Adds parent_ids to datasources in the tree based upon the
        ordered list provided by the ESM. All the datasources below
        a Receiver row have it's id set as their parent ID.

        Returns:
            List of datasource dicts
        """
        _pid = '0'
        esm_dev_id = ['14']
        esm_mfe_dev_id = ['19', '21', '22', '24']
        nitro_dev_id = ['2', '4', '10', '12', '13', '15']
        datasource_dev_id = ['3', '5', '7', '17', '20', '23', '256']
        
                   
        for device in devtree:
            if device['desc_id'] in esm_dev_id:
                esm_name = device['name']
                esm_id = device['ds_id']
                device['parent_name'] = 'n/a'
                device['parent_id'] = '0'
                continue

            if device['desc_id'] in esm_mfe_dev_id:
                parent_name = device['name']
                parent_id = device['ds_id']
                device['parent_name'] = 'n/a'
                device['parent_id'] = '0'
                continue
            
            if device['desc_id'] in nitro_dev_id:
                device['parent_name'] = esm_name
                device['parent_id'] = esm_id
                parent_name = device['name']
                pid = device['ds_id']
                continue

            if device['desc_id'] in datasource_dev_id:
                device['parent_name'] = parent_name
                device['parent_id'] = pid
            else:
                device['parent_name'] = 'n/a'
                device['parent_id'] = 'n/a'

        return devtree

    def _get_client_containers(self, devtree):
        """
        Filters DevTree for datasources that have client datasources.
        
        Returns:
            List of datasource dicts that have clients
        """
        return [ds for ds in devtree
                if ds['desc_id'] == "3"
                if int(ds['client_groups']) > 0]

    def _merge_clients(self, containers, devtree):
        _cidx = 0
        _didx = 0
        for cont in containers:
            clients = self._get_clients(cont['ds_id'])
            clients = self._format_clients(clients)
            cont['idx'] = cont['idx'] + _didx
            _pidx = cont['idx']
            _cidx = _pidx + 1
            for client in clients:
                client['parent_id'] = cont['ds_id']
                client['idx'] = _cidx
                _cidx += 1
                _didx += 1
            devtree[_pidx:_pidx] = clients
        return devtree

    def _get_clients(self, ds_id):
        """
        Get list of raw client strings.

        Args:
            ds_id (str): Parent ds_id(s) are collected on init
            ftoken (str): Set and used after requesting clients for ds_id

        Returns:
            List of strings representing unparsed client datasources
        """

        file = self.nitro.request('req_client_str', ds_id=ds_id)['FTOKEN']
        pos = 0
        nbytes = 0
        resp = self.nitro.request('get_rfile2', ftoken=file, pos=pos, nbytes=nbytes)

        if resp['FSIZE'] == resp['BREAD']:
            data = resp['DATA']
            self.nitro.request('del_rfile', ftoken=file)
            return dehexify(data)
        
        data = []
        data.append(resp['DATA'])
        file_size = int(resp['FSIZE'])
        collected = int(resp['BREAD'])

        while file_size > collected:
            pos += int(resp['BREAD'])
            nbytes = file_size - collected
            resp = self.nitro.request('get_rfile2', ftoken=file, pos=pos, nbytes=nbytes)
            collected += int(resp['BREAD'])
            data.append(resp['DATA'])

        resp = self.nitro.request('del_rfile', ftoken=file)
        return dehexify(''.join(data))


    def _format_clients(self, clients):
        """
        Parse key fields from _get_clients() output.

        Returns:
            list of dicts
        """
        clients = StringIO(clients)
        clients = csv.reader(clients, delimiter=',')

        clients_lod = []
        for row in clients:
            if len(row) < 13:
                continue

            ds_fields = {'desc_id': "256",
                          'name': row[1],
                          'ds_id': row[0],
                          'enabled': row[2],
                          'ds_ip': row[3],
                          'hostname': row[4],
                          'type_id': row[5],
                          'vendor': row[6],
                          'model': row[7],
                          'tz_id': row[8],
                          'date_order': row[9],
                          'port': row[11],
                          'syslog_tls': row[12],
                          'client_groups': "0",
                          'zone_name': '',
                          'zone_id': '',
                          'client': True
                               }
            clients_lod.append(ds_fields)
        return clients_lod        

    def _get_zonetree(self):
        """
        Retrieve zone data.
        
        Returns:
            str: device tree string sorted by zones
        """        
        resp = self.nitro.request('get_zones_devtree')
        return dehexify(resp['ITEMS'])
        
    def _insert_zone_names(self, zonetree, devtree):
        """
        Args:
            zonetree (str): Built by self._get_zonetree
        
        Returns:
            List of dicts (str: str) devices by zone
        """
        zone_name = None
        zonetree = StringIO(zonetree)
        zonetree = csv.reader(zonetree, delimiter=',')

        for row in zonetree:
            if row[0] == '1':
                zone_name = row[1]
                if zone_name == 'Undefined':
                    zone_name = ''
                continue
            for device in devtree:
                if device['ds_id'] == row[2]:
                    device['zone_name'] = zone_name
        return devtree

    def _get_zone_map(self):
        """
        Builds a table of zone names to zone ids.
        
        Returns:
            dict (str: str) zone name : zone ids
        """
        zone_map = {}
        resp = self.nitro.request('zonetree')

        if not resp:
            return zone_map
        for zone in resp:
            zone_map[zone['name']] = zone['id']['value']
            for szone in zone['subZones']:
                zone_map[szone['name']] = szone['id']['value']
        return zone_map
        
    def _insert_zone_ids(self, zone_map, devtree):
        """
        """
        for device in devtree:
            if device['zone_name'] in zone_map.keys():
                device['zone_id'] = zone_map.get(device['zone_name'])
            else:
                device['zone_id'] = '0'
        return devtree
        
    def _insert_venmods(self):
        """
        Populates vendor/model fields for any datasources 
        
        Returns:
            List of datasource dicts - devtree
        """
        for self._ds in self._devtree:
            if not self._ds['vendor'] and self._ds['desc_id'] == '3': 
                self._ds['vendor'], self._ds['model'] = ESM().type_id_to_venmod(self._ds['type_id'])
        return self._devtree_lod
    
    def _insert_desc_names(self):
        """
        Populates the devtree with desc_names matching the desc_ids
        
        Returns:
            List of datasource dicts - devtree
        
        """
        self._type_map = {'1': 'zone',
                        '2': 'ERC',
                        '3': 'datasource',
                        '4': 'Database Event Monitor (DBM)',
                        '5': 'DBM Database',
                        '7': 'Policy Auditor',
                        '10': 'Application Data Monitor (ADM)',
                        '12': 'ELM',
                        '14': 'Local ESM',
                        '15': 'Advanced Correlation Engine (ACE)',
                        '16': 'Asset datasource',
                        '17': 'Score-based Correlation',
                        '19': 'McAfee ePolicy Orchestrator (ePO)',
                        '20': 'EPO',
                        '21': 'McAfee Network Security Manager (NSM)',
                        '22': 'McAfee Network Security Platform (NSP)',
                        '23': 'NSP Port',
                        '24': 'McAfee Vulnerability Manager (MVM)',
                        '25': 'Enterprise Log Search (ELS)',
                        '254': 'client_group',
                        '256': 'client'}

        for self._ds in self._devtree:
            if self._ds['desc_id'] in self._type_map:
                self._ds['desc'] = self._type_map[self._ds['desc_id']]
        return self._devtree
        
                        
    def _get_last_times(self):
        """
        Returns:
            string with datasource names and last event times.
        """
        resp = self.nitro.request('ds_last_times')
        return dehexify(resp['ITEMS'])

    def _format_times(self, last_times):
        """
        Formats the output of _get_last_times

        Args:
            last_times (str): string output from _get_last_times()

        Returns:
            list of dicts - [{'name', 'model', 'last_time'}]
        """
            
        last_times = StringIO(last_times)
        last_times = csv.reader(last_times, delimiter=',')
        last_times_lod = []
        for row in last_times:
            if len(row) == 5:
                time_d = {}
                time_d['name'] = row[0]
                time_d['model'] = row[2]
                if row[3]:
                    time_d['last_time'] = row[3]
                else:
                    time_d['last_time'] = 'never'
                last_times_lod.append(time_d)
        return last_times_lod

    def _insert_ds_last_times(self, last_times, devtree):
        """
        Parse event times str and insert it into the _devtree

        Returns:
            List of datasource dicts - the devtree
        """
        for device in devtree:
            for d_time in last_times:
                if device['name'] == d_time['name']:
                    device['model'] = d_time['model']
                    device['last_time'] = d_time['last_time']
        return devtree

    def _filter_bogus_ds(self, devtree):
        """Filters objects that inaccurately show up as datasources sometimes.
        
        Arguments:
            devtree (list) -- the devtree
        """
        type_filter = ['1', '16', '254']
        return [ds for ds in devtree if ds['desc_id'] not in type_filter]

    def add(self, kwargs):
            """
            Adds a datasource. 

            Args:
                **kwargs: datasource attributes
            
            Attributes:
                client (bool): designate a client datasource (not child)
                name (str): name of datasource (req)
                parent_id (str): id of parent device (req)
                ds_ip (str): ip of datasource (ip or hostname required)
                hostname (str): hostname of datasource 
                type_id (str): type of datasource (req)
                enabled (bool): enabled or not (default: True)
                tz_id (str): timezone of datasource (default UTC: 8)
                    Examples (tz_id only): PST: 27, MST: 12, CST: 11, EST: 32 
                syslog_tls (bool): datasource uses syslog tls
            
            Returns:
                datasource id (str)
                    or None on Error            
            """
            p = self._validate_ds_params(kwargs)

            if self.nitro.version.startswith(('9', '10', '11.0', '11.1')):
                ds_id = self.nitro.request('add_ds_11_1_3', 
                                            parent_id=p['parent_id'],
                                            name=p['name'],
                                            ds_ip=p['ds_ip'],
                                            type_id=p['type_id'],
                                            zone_id=p['zone_id'],
                                            enabled=p['enabled'],
                                            url=p['url'],
                                            ds_id=0,
                                            child_enabled='false',
                                            child_count=0,
                                            child_type=0,
                                            idm_id=0,
                                            parameters=p['parameters'])
            else:
                ds_id = self.nitro.request('add_ds_11_2_1', 
                                            parent_id=p['parent_id'],
                                            name=p['name'],
                                            ds_ip=p['ds_ip'],
                                            type_id=p['type_id'],
                                            zone_id=p['zone_id'],
                                            enabled=p['enabled'],
                                            url=p['url'],
                                            parameters=p['parameters'])
            return ds_id

    def _validate_ds_params(self, p):
        """Validate parameters for new datasource.
        
        Arguments:
            p (dict) -- datasource parameters
        
        Returns:
            datasource dict with normalized values
        
            or False if something is invalid.
        """
        if not p.get('name'):
            logging.error('Error: New datasource requires "name".')
            return

        if not p.get('ds_ip'):
             if p.get('ip'):
                 p['ds_ip'] = p['ip']
             else:
                if not p.get('hostname'):
                    logging.error('Error: New datasource requires "ip" or "hostname".')
                    return
        
        if not p.get('hostname'):
            p['hostname'] = ''

        if not p.get('parent_id'):
            p['parent_id'] = 0

        #p = self._validate_ds_tz_id(p)
        #if not p:
        #   return

        if p.get('enabled') == False:
            p['enabled'] = 'false'
        else:
            p['enabled'] = 'true'

        if p.get('client'):
            if not p.get('dorder'):
                p['dorder'] = 0

            if not p.get('maskflag'):
                p['maskflag'] = 'true'

            if not p.get('port'):
                p['port'] = 0

            if not p.get('syslog_tls'):
                p['syslog_tls'] = 'F'
        else:
            if not p.get('type_id'):
                logging.error('Error: New datasource requires "type_id".')
                return

            if not p.get('zone_id'):
                p['zone_id'] = 0

            if not p.get('url'):
                p['url'] = ''

        _base_vars = ['name', 'ds_ip', 'ip', 'client', 'hostname', 'parent_id', 
                            'enabled', 'zone_id', 'type_id', 'childEnabled', 'childCount',
                            'idmId', 'url', 'parameters', 'childType']
        p['parameters'] = []
        for key, val in p.items():
            if key not in _base_vars:
                p['parameters'].append({key: val})
        p = {k: v for k, v in p.items() if k in _base_vars}

        return p

    def _validate_ds_tz_id(self, p):
        """Validates datasource time zone id.
        
        Arguments:
            p (dict): datasource param
        
        Returns:
            dict of datasource params or None if invalid
        """
        if p.get('tz_id'):
            try:
                if not 0 <= int(p.get('tz_id')) <= 75:
                    logging.error('Error: New datasource "tz_id" must be int between 1-74.')
                    return
            except ValueError:
                logging.error('Error: New datasource "tz_id" must be int between 1-74.')
                return
        else:
            p['tz_id'] = 0
        
        return p
