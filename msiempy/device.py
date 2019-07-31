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
from .utils import dehexify

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

    def version(self):
        """
        Returns:
            str. ESM short version.

        Example:
            '10.0.2'
        """
        return self.buildstamp().split()[0]

    def buildstamp(self):
        """
        Returns:
            str. ESM buildstamp.

        Example:
            '10.0.2 20170516001031'
        """
        #return self.post('essmgtGetBuildStamp')['buildStamp']
        return self.nitro.request('build_stamp')['buildStamp']

    def time(self):
        """
        Returns:
            str. ESM time (GMT).

        Example:
            '2017-07-06T12:21:59.0+0000'
        """
        self._esmtime = self.nitro.request("get_esm_time")
        return self._esmtime['value']


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
        #return self.post("sysGetSysInfo")
        return self.nitro.request("get_sys_info")

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
        self._fields = ['autoBackupEnabled',
                        'autoBackupDay',
                        'autoBackupHour',
                        'autoBackupHour',
                        'backupNextTime']

        return {self.key: self.val for self.key, self.val in self.status().items()
                if self.key in self._fields}

    def callhome(self):
        """
        Returns:
            bool. True/False if there is currently a callhome connection
        """
        self._callhome_ip = self.status()['callHomeIp']
        if self._callhome_ip:
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
        #self.method, self.data = self._get_params('get_recs')
        #self._rec_list = self.post(self.method, self.data)
        self._rec_list=self.nitro.request('get_recs')

        return [(_rec['name'], _rec['id']['id'])for _rec in self._rec_list]
                
    @lru_cache(maxsize=None)   
    def _get_timezones(self):
        """
        Gets list of timezones from the ESM.
        
        Returns:
            str. Raw return string from ESM including 
        """
        #return self.post('userGetTimeZones')
        return self.nitro.request('')
        
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
        self.tz_resp = self._get_timezones()
        return [(self.tz['id']['value'], self.tz['name'], self.tz['offset']) 
                  for self.tz in self.tz_resp]
                   
        
    def timezones(self):
        """
        Builds table of ESM timezones and names only. No offsets.
        
        Returns:
            dict. {timezone_id, timezone_name}
        """
        self.tz_resp = self._get_timezones()
        self.tz_table = {str(self.tz['id']['value']): self.tz['name']
                            for self.tz in self.tz_resp}
        return self.tz_table

    def tz_name_to_id(self, tz_name):
        """
        Args:
            tz_name (str): Case sensitive, exact match timezone name
            
        Returns:
            str. Timezone id or None if there is no match
        """
        self.tz_reverse = {tz_name: tz_id 
                            for tz_id, tz_name in self.timezones().items()}
        try:
            return self.tz_reverse[tz_name]
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
        self.type_id = type_id
        self.ds_types = self._get_ds_types()
        for self.venmod in self.ds_types:
            if str(self.venmod[0]) == str(self.type_id):
                return (self.venmod[1], self.venmod[2])
        return(('Unkown vendor for type_id {}'.format(type_id),'Unkown vendor'))

    def venmod_to_type_id(self, vendor, model):
        """
        Args:
            vendor (str): Exact vendor string including puncuation
            model (str): Exact vendor string including puncuation
        
        Returns:
            str. Matching type_id or None if there is no match
        """
        self.vendor = vendor
        self.model = model
        self.ds_types = self._get_ds_types()
        for self.venmod in self.ds_types:
            if self.vendor == self.venmod[1]:
                if self.model == self.venmod[2]:
                    return str(self.venmod[0])
        
     
    @lru_cache(maxsize=None)   
    def _get_ds_types(self):
        """
        Retrieves device table from ESM
                    
        Returns:
            list. of tuples output from callback: _format_ds_types()

        Note:
            rec_id (str): self.rec_id assigned in method
        """
        self.rec_id = self.recs()[0][1]

        #self.method, self.data = self._get_params('get_dstypes')
        #self.venmods = self.post(self.method, self.data, self._format_ds_types)

        self.venmods=self.nitro.request('get_dstypes', rec_id=self.rec_id)

        return self.venmods
                    
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
        self._venmods = venmods
        return [(_mod['id']['id'], _ven['name'], _mod['name'],)
                    for _ven in self._venmods['vendors']
                    for _mod in _ven['models']]

class DataSource(NitroDict):
    """
    A DataSource object represents a validated datasource configuration.
    
    This object represents current datasources as well and acts as a 
    validation template for new datasources 
    
    Public Methods:
        add()       Adds the datasource object to the ESM.
        
        edit()      Edits a datasource parameter - Not yet implemented.
        
        delete()    Deletes the datasource and ALL associated data.
        
        props()     Returns a JSON string of datasource properties.
        
        __len__     Returns the number of properties set.
        
        __repr__    Print the datasource, returns props()
        
    """

    def __len__(self):
        """
        Count up the datasource attributes
        
        Returns:
            int: Number of DataSource attributes set
        """
        return len(self.props())
            
    def __repr__(self):
        """
        Dumps the datasource settings in json
        
        Returns:
            str: Datasource attributes as JSON
        """        
        return json.dumps(self.props())
    
    def __init__(self, *args, **kwargs):
        """
        Inits the datasource
        
        Args: 
            kwargs:
            
                Can represent any valid datasource attribute, but at 
                a mininum, the following arguments are required to 
                init the object:
            
                name (str): datasource name
                type_id (str): datasource type_id
                parent_id (str): datasource parent_id
                ds_ip (str): unique IP address of datasource*
                hostname (str): unique hostname*
                
                + Any additional valid params...
                            
            Note:
            * Both hostname and ip can be set, but at least one of them
              MUST be set.
            
        """
        
        super().__init__(*args)#, **kwargs)
                
        self._devtree = DevTree()

        self.name=''
        self.parent_id=None

        self.ds_ip = ''
        self.child_enabled = "false"
        self.child_count = "0"
        self.child_type = "0"
        self.zone_id = "0"
        self.url = None
        self.enabled = 'true'
        self.idm_id = "0"
        self.hostname = None
        self.tz_id = None
        self.dorder = None
        self.maskflag = None
        self.port = None
        self.syslog_tls = None
        self.vendor = None
        self.model = None
        self.client_groups = None
        self._prop = None
        self._pval = None
        self.__dict__.update(kwargs)
        
        self._dsfields = ['parent_id', 'name','ds_id', 'type_id', 'rec_ip',
                           'child_enabled', 'child_count', 'child_type',
                           'ds_ip', 'zone_id', 'url', 'enabled', 'idm_id']

        self.parameters = [{key: val 
                            for key, val in kwargs.items()
                            if key not in self._dsfields}]

    def _validate_name(self, name):
        """
        Returns:
            None
        
        Raises:
            KeyError: if name is missing or invalid
        """
        try:
            if re.search('^[a-zA-Z0-9_-]{1,100}$', self.name):
                pass
            else:
                raise KeyError('Valid name required for DataSource')
        except KeyError:
            raise KeyError('Valid name required for DataSource')
    
    def props(self):
        """
        Dumps the datasource settings
        
        Returns:
            str: Datasource attributes as JSON
        """        
        return {self._prop: self._pval
            for self._prop, self._pval in self.__dict__.items()
            if not self._prop.startswith('_')}
                    
    def add(self, client=False):
        """
        Adds a datasource
        
        Returns:
            None 
        
        Raises:
            ESMException: Will be raised if trying to add a duplicate
            datasource or if something else goes wrong.
        """
        self._search_dups = partial(self._devtree.search, rec_id=self.parent_id)
        if self._search_dups(self.name, zone_id=self.zone_id):
            raise NitroError('Datasource name already exists.'
                                'Cannot add datasource: {}'.format(self.name))
        if self._search_dups(self.ds_ip, zone_id=self.zone_id):
            raise NitroError('Datasource IP already exists.' 
                                'Cannot add datasource: {}'.format(self.ds_ip))
        if client:
            #self._method, self._data = self._get_params('add_client')
            self._resp=self.nitro.request('add_client',
                                    parent_id=self.parent_id,
                                    name=self.name, 
                                    enabled=self.enabled, 
                                    ds_ip=self.ds_ip,
                                    hostname=self.hostname, 
                                    type_id=self.data['type_id'], 
                                    tz_id=self.tz_id, 
                                    dorder=self.dorder, 
                                    maskflag=self.maskflag, 
                                    port=self.port, 
                                    syslog_tls=self.syslog_tls)
        else:
            self._resp=self.nitro.request('add_ds', 
                                    parent_id=self.parent_id,
                                    name=self.name, 
                                    ds_id=self.data['ds_id'], 
                                    type_id=self.data['type_id'], 
                                    child_enabled=self.child_enabled, 
                                    child_count=self.child_count, 
                                    child_type=self.child_type, 
                                    ds_ip=self.ds_ip, 
                                    zone_id=self.zone_id, 
                                    url=self.url, 
                                    enabled=self.enabled, 
                                    idm_id=self.idm_id, 
                                    parameters=self.parameters)
            #self._method, self._data = self._get_params('add_ds')

        #self._resp = self.post(self._method, self._data)

        if client:
            try:
                self._err_code = self._resp['EC']
                if self._err_code == '0':
                    return None
            except KeyError:
                raise NitroError('Unexpected error occured. ' 
                                    'DS may not have been added.')
        try:
            self._ds_id = self._resp.get('id')
            return None
        except (KeyError, AttributeError):
            pass
        
    def delete(self):
        """
        Deletes a datasource
        
        Args:
            ds_id (str). DataSource ID
            rec_id (str). Receiver ID / DataSource parent_id
            
        Warning:
            This really does delete the datasource and ALL data
            ever collected for that datasource.
        
        Returns:
            None
        
        Raises:
            ESMException: If the datasource to be deleted is 
                still in the tree after being deleted an Exception 
                will be raised.
        """
        #self._method, self._data = self._get_params('del_ds')
        #self._resp = self.post(self._method, self._data)

        self._resp=self.nitro.request('del_ds', parent_id=self.parent_id, ds_id=self._ds_id)
        
    def _ds_details(self):
        """
        Queries the ESM for datasource details
        
        Returns:
            dict (str, str) with some subdicts 
        
        Warning:
            Don't create a situation where this gets called for every
            datasource as it will not scale.
        """
        #self._method, self._data = self._get_params('ds_details')
        #return self.post(self._method, self._data)
        return self.data_from_id(id=self._ds_id)

    def data_from_id(self, id):
        return self.nitro.request('ds_details', ds_id=id)


    @staticmethod
    def valid_ip(ipaddr):
        """
        Validates IPv4/v6 address or raises ValueError.

        Args:
            ipaddr (str): IP address

        Returns:
            True if valid, False if not.
            
        Raises:
            ValueError: It's the wrong value if it's not valid.
        """
        try:
            ipaddr = str(ipaddress.ip_address(ipaddr))
            return True
        except ValueError:
            return False
     
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
        if not DevTree._DevTree:
            self._build_devtree()

    def __len__(self):
        """
        Returns the count of devices in the device tree.
        """
        return len(DevTree._DevTree)
        
    def __iter__(self):
        """
        Returns:
            Generator with datasource objects.
        """
        self._ds_desc_ids = ['3', '256']
        for self._ds in DevTree._DevTree:
            if self._ds['desc_id'] in self._ds_desc_ids:
                yield DataSource(adict=self._ds)

    def __contains__(self, term):
        """
        Returns:
            bool: True/False the name or IP matches the provided search term.
        """
        self._cterm = term
        if self.search(self._cterm):
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
        self._term = term.lower()
        self._rec_id = rec_id
        self._zone_id = zone_id

        self._search_fields = ['ds_ip', 'name', 'hostname', 'ds_id']

        self._found = [self._ds for self._ds in DevTree._DevTree 
                            for self._field in self._search_fields 
                            if self._ds[self._field].lower() == self._term 
                            if self._ds['zone_id'] == self._zone_id]

        if self._rec_id and len(self._found) > 1:
            self._found = [self._ds for self._ds in self._found 
                            if self._ds['parent_id'] == self._rec_id]
        
        if self._found:
            return DataSource(**self._found[0])
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
        self._field = field
        self._term = term
        self._zone_id = zone_id
        
        if not self._field:
            raise ValueError('DataSource field required')

        if not self._term:
            raise ValueError('DataSource field value required')

        return (DataSource(adict=self._ds) for self._ds in DevTree._DevTree
                        if self._ds.get(self._field) == self._term)
                       
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
        self._ones = ['14']
        self._twos = ['2', '4', '10', '12', '15', '25']
        self._threes = ['3', '5', '7', '17', '19', '20', '21', '24', '254']
        self._fours = ['7','17', '23', '256']

        for self._ds in DevTree._DevTree:
            if self._ds['desc_id'] in self._ones:
                self._ds['depth'] = '1'
            elif self._ds['desc_id'] in self._twos:
                self._ds['depth'] = '2'
            elif self._ds['desc_id'] in self._threes:
                self._ds['depth'] = '3'
            else:
                self._ds['depth'] = '4'
            self._steptree.append((self._ds['idx'], self._ds['name'], 
                                    self._ds['ds_ip'], self._ds['depth'],))
        return self._steptree

                    
    def refresh(self):
        """
        Rebuilds the devtree
        """
        self._build_devtree()
        
    def get_ds_times(self):
        """
        """
        self._last_times = self._get_last_event_times()
        self._insert_ds_last_times()#self._last_times)
        return self._last_times
        
    def recs(self):
        """
        Returns:
            list of Receiver dicts (str:str)
        """
        return [self._rec for self._rec in DevTree._DevTree 
                    if self._rec['desc_id'] == '2']
    
    def _build_devtree(self):
        """
        Coordinates assembly of the devtree object
        """
        self._devtree = self._get_devtree()
        self._devtree = self._devtree_to_lod()
        self._devtree = self._insert_rec_info()
        self._client_containers = self._get_client_containers()

        """
        This next bit of code gets and formats the clients for each
        container and inserts them back into the devtree.
        
        The tricky part is keeping the devtree in order and keeping 
        index labels consistent for all of the devices while 
        inserting new devices into the middle with their own index
        labels. Kind of like changing a tire on a moving car...
        
        pidx - parent idx is the original index value of the parent
                this does not increment
                
        cidx - client idx is incremented starting after the pidx
        
        didx - stores the delta between different containers to 
               keep it all in sync.
        """
        self._cidx = 0
        self._didx = 0
        for self._container in self._client_containers:
            self._raw_clients = self._get_raw_clients(self._container['ds_id'])
            self._clients_lod = self._clients_to_lod(self._raw_clients)
            self._container['idx'] = self._container['idx'] + self._didx
            self._pidx = self._container['idx']
            self._cidx = self._pidx + 1 
            for self._client in self._clients_lod:
                self._client['parent_id'] = self._container['ds_id']
                self._client['idx'] = self._cidx 
                self._cidx += 1 
                self._didx += 1
            self._devtree[self._pidx:self._pidx] = self._clients_lod 
            
        self._zonetree = self._get_zonetree()
        self._devtree = self._insert_zone_names()
        self._zone_map = self._get_zone_map()
        self._devtree = self._insert_zone_ids()            
        self._devtree = self._insert_venmods()
        self._devtree = self._insert_desc_names()
        self._last_times = self._get_last_event_times()
        self._insert_ds_last_times()
        DevTree._DevTree = self._devtree
               
    def _get_devtree(self):
        """
        Returns:
            ESM device tree; raw, but ordered, string.
            Does not include client datasources.
        """
        #self._method, self._data = self._get_params('get_devtree')
        #self._resp = self.post(self._method, self._data)
        self._resp=self.nitro.request('get_devtree')
        return dehexify(self._resp['ITEMS'])

    def _devtree_to_lod(self):
        """
        Parse key fields from raw device strings into datasource dicts
        
        Returns: 
            List of datasource dicts
        """
        self._devtree_io = StringIO(self._devtree)
        self._devtree_csv = csv.reader(self._devtree_io, delimiter=',')
        self._devtree_lod = []

        for self._idx, self._row in enumerate(self._devtree_csv, start=1):
            if len(self._row) == 0:
                continue
            
            if self._row[0] == '16':  # Get rid of duplicate 'asset' devices
                continue
            
            if self._row[2] == "3":  # Client group datasource group containers
                self._row.pop(0)     # are fake datasources that seemingly have
                self._row.pop(0)     # two uneeded fields at the beginning.

            if self._row[16] == 'TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT':
                self._row[16] = '0'  # Get rid of weird type-id for N/A devices
                
            self._ds_fields = {'idx': self._idx,
                                'desc_id': self._row[0],
                                'name': self._row[1],
                                'ds_id': self._row[2],
                                'enabled': self._row[15],
                                'ds_ip': self._row[27],
                                'hostname' : self._row[28],
                                'type_id': self._row[16],
                                'vendor': '',
                                'model': '',
                                'tz_id': '',
                                'date_order': '',
                                'port': '',
                                'syslog_tls': '',
                                'client_groups': self._row[29],
                                'zone_name': '',
                                'zone_id': '',
                                'client': False
                              }
            self._devtree_lod.append(self._ds_fields)
        return self._devtree_lod

    def _insert_rec_info(self):
        """
        Adds parent_ids to datasources in the tree based upon the 
        ordered list provided by the ESM. All the datasources below
        a Receiver row have it's id set as their parent ID.
        
        Returns:
            List of datasource dicts
        """
        self._pid = '0'
        self._rec_name = ''
        for self._ds in self._devtree:
            if self._ds['desc_id'] in ['2', '4', '15']:
                self._pid = self._ds['ds_id']
                self._rec_name = self._ds['name']
                continue
            
            if self._ds['desc_id'] in ['3', '5', '7', '17']:
                self._ds['parent_id'] = self._pid
                self._ds['rec_name'] = self._rec_name
        return self._devtree

    def _get_client_containers(self):
        """
        Filters DevTree for datasources that have client datasources.
        
        Returns:
            List of datasource dicts that have clients
        """
        return [self._ds for self._ds in self._devtree
                                if self._ds['desc_id'] == "3" 
                                if int(self._ds['client_groups']) > 0]
        
    def _get_raw_clients(self, ds_id):
        """
        Get list of raw client strings.
        
        Args:
            ds_id (str): Parent ds_id(s) are collected on init
            ftoken (str): Set and used after requesting clients for ds_id
            
        Returns:
            List of strings representing unparsed client datasources
        """
        self._ds_id = ds_id
        #self._method, self._data = self._get_params('req_client_str')
        #self._resp = self.post(self._method, self._data)

        self._resp = self.nitro.request('req_client_str', _ds_id=ds_id)

        self._ftoken = self._resp['FTOKEN']
        return self._get_file(self._ftoken)

    def _get_client_list(self, group_id):
        """
        Finds client group
        
        Args:
            DSID (str): Parent datasource ID set to self._ds_id
        
        Returns:
            Response dict with FTOKEN required to get the data file
        
        """
        self.group_id = group_id

        #self._method, self._data = self._get_params('req_client_str')
        #self._resp = self.post(self._method, self._data)
        self._resp = self.nitro.request('req_client_str', _ds_id=self._ds_id)

        return self._resp

    def _get_file(self, ftoken):
        """
        Exchanges token for file
        
        Args:
            ftoken (str): instance name set by 
        
        """
        self.ftoken = ftoken

        #self._method, self._data = self._get_params('get_rfile')
        #self._resp = self.post(self._method, self._data)
        
        self._resp = self.nitro.request('get_rfile', _ftoken=ftoken)

        self._resp = dehexify(self._resp['DATA'])
        return self._resp

    def _clients_to_lod(self, clients):
        """
        Parse key fields from _get_clients() output.
        
        Returns:
            list of dicts
        """
        self._clients = clients

        self._clients_io = StringIO(self._clients)
        self._clients_csv = csv.reader(self._clients_io, delimiter=',')

        self._clients_lod = []
        for self._row in self._clients_csv:
            if len(self._row) < 2:
                continue

            self._ds_fields = {'desc_id': "256",
                              'name': self._row[1],
                              'ds_id': self._row[0],
                              'enabled': self._row[2],
                              'ds_ip': self._row[3],
                              'hostname' : self._row[4],
                              'type_id': self._row[5],
                              'vendor': self._row[6],
                              'model': self._row[7],
                              'tz_id': self._row[8],
                              'date_order': self._row[9],
                              'port': self._row[11],
                              'syslog_tls': self._row[12],
                              'client_groups': "0",
                              'zone_name': '',
                              'zone_id': '',
                              'client': True
                              }
            self._clients_lod.append(self._ds_fields)
        return self._clients_lod
            
    def _get_zonetree(self):
        """
        Abuses the device tree for zone data.
        
        Returns:
            str: device tree string sorted by zones
        """
        
        #self._method, self._data = self._get_params('get_zones_devtree')
        #self._resp = self.post(self._method, self._data)
        self._resp=self.nitro.request('get_zones_devtree')
        
        return dehexify(self._resp['ITEMS'])
        
    def _insert_zone_names(self):
        """
        Args:
            _zonetree (str): set in __init__
        
        Returns:
            List of dicts (str: str) devices by zone
        """
        self._zone_name = None
        self._zonetree_io = StringIO(self._zonetree)
        self._zonetree_csv = csv.reader(self._zonetree_io, delimiter=',')
        self._zonetree_lod = []

        for self._row in self._zonetree_csv:
            if self._row[0] == '1':
                self._zone_name = self._row[1]
                if self._zone_name == 'Undefined':
                    self._zone_name = ''
                continue
            for self._dev in self._devtree:
                if self._dev['ds_id'] == self._row[2]:
                    self._dev['zone_name'] = self._zone_name
        return self._devtree

    def _get_zone_map(self):
        """
        Builds a table of zone names to zone ids.
        
        Returns:
            dict (str: str) zone name : zone ids
        """
        self._zone_map = {}

        #self._method, self._data = self._get_params('zonetree')
        #self._resp = self.post(self._method, self._data)

        self._resp=self.nitro.request('zonetree')

        for self._zone in self._resp:
            self._zone_map[self._zone['name']] = self._zone['id']['value']
            for self._szone in self._zone['subZones']:
                self._zone_map[self._szone['name']] = self._szone['id']['value']
        return self._zone_map
        
    def _insert_zone_ids(self):
        """
        """
        for self._dev in self._devtree:
            if self._dev['zone_name'] in self._zone_map.keys():
                self._dev['zone_id'] = self._zone_map.get(self._dev['zone_name'])
            else:
                self._dev['zone_id'] = '0'
        return self._devtree
        
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
        
    def _get_client_grps(self):
        """
        Returns:
            dict (str:str) fake datasource dicts that represent client 
            containers on the device tree.
        """
        return [self._dev for self._dev in DevTree._DevTree 
                        if int(self._dev['client_groups']) > 0 
                        and self._dev['desc_id'] == '3']
                        
    def _get_last_event_times(self):
        """
        Returns:
            string with datasource names and last event times.
        """
        #self._method, self._data = self._get_params('ds_last_times')
        #self._resp = self.post(self._method, self._data)

        self._resp = self.nitro.request('ds_last_times')
        return dehexify(self._resp['ITEMS'])

    def _insert_ds_last_times(self):
        """
        Parse event times str and insert it into the _devtree
        
        Returns: 
            List of datasource dicts - the devtree
        """
        self._last_times_io = StringIO(self._last_times)
        self._last_times_csv = csv.reader(self._last_times_io, delimiter=',')
        for self._row in self._last_times_csv:
            for self._ds in self._devtree:
                self._ds['last_time'] = self._row[3]
            else: 
                self._ds['last_time'] = ''
        return self._devtree