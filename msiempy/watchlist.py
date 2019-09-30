# -*- coding: utf-8 -*-
"""Provide watchlist management."""

import logging
import collections
log = logging.getLogger('msiempy')

from . import NitroDict, NitroList

class WatchlistManager(NitroList):
    """
    Summary of ESM watchlists.

    Example:
        wlman = WatchlistManager()
        for wl in wlman:
            if wl['name'] == 'IPs-To-Block-On-IPS-24hrs': break
        wl.add_values(['1.1.1.2', '2.2.2.1', '3.3.3.1'])

    """

    def __init__(self, *args, **kwargs):
        """
        Initialize the watchlist manager.
        """
        super().__init__(*args, **kwargs)
        self.get_watchlist_summary()

    def get_watchlist_summary(self):
        self.data = self.nitro.request('get_watchlists_no_filters',
            hidden=False, dynamic=False, writeOnly=False, indexedOnly=False)

        #Casting all data to Watchlist objects, better way to do it ?
        collections.UserList.__init__(self,
            [Watchlist(adict=item) for item in self.data
                if isinstance(item, (dict, NitroDict))])

    def load_details(self):
        """
        Load a summary of existing watchlists.
        """
        self.perform(Watchlist.load_details, asynch=False, progress=True)

    def refresh(self):
        """
        Reloads the watchlist summary.
        """
        self.get_watchlist_summary()

    def add(self, name, wl_type):
        """
        Create a static watchlist.
        Args:
            name (str): Name of the watchlist.
            wl_type (str): Watchlist data type.
                Get the list of types with: 'get_wl_types'
                Most common types are: IPAddress,
                                       Hash,
                                       SHA1,
                                       DSIDSigID,
                                       Port,
                                       MacAddress,
                                       NormID,
                                       AppID,
                                       CommandID,
                                       DomainID,
                                       HostID,
                                       ObjectID,
                                       Filename,
                                       File_Hash
        """
        for wl in self.data:
            if wl.get('name') == name:
                logging.error('Cannot add: {} watchlist already exists.'.format(name))
                return
        self.nitro.request('add_watchlist', name=name, wl_type=wl_type)
        self.refresh()

    def remove(self, wl_id_list):
        """
        Remove watchlist(s).

        Args:
            wl_ids (list): list of watchlist IDs

        Example:
            1, 2, 3
        """
        self.nitro.request('remove_watchlists', wl_id_list=wl_id_list)

    def get_wl_types(self):
        """
        Get a list of watchlist types.

        Returns:
            list of watchlist types.
        """
        return self.nitro.request('get_wl_types')

class Watchlist(NitroDict):
    """

    Complete list of watchlist fields (not values) once load with load_details()

    Dictionary keys:

    - `name`: The name of the watchlist
    - `type`: The watchlist type
    - `customType`: The watchlist custom type (custom field)
    - `dynamic`: Whether this watchlist is dynamic
    - `hidden`:  Whether this watchlist is hidden
    - `scored`: Whether this watchlist has a scoring component (GTI for example)
    - `valueCount`: The number of values in this watchlist
    - `active`: Whether this watchlist is a active
    - `errorMsg`: The error message, if there is one associated with this watchlist
    - `source`: source
    - `id`: The id of the watchlist
    - `values`: values
    - And others...

    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if id in kwargs:
            self.id = id
        else:
            self.id = 0
        self.name = None
        self.active = True
        self.type = None
        self.type_id = None
        self.custom_type = False
        self.dynamic = False
        self.source = 0
        self.search = None
        self.update_type = 'EVERY_SO_MANY_MINUTES'
        self.update_day = 0
        self.update_min = 0
        self.ipsid = 0
        self.job_tracker_url = None
        self.job_tracker_port = None
        self.post_args = None
        self.ssl_check = False
        self.method = 0
        self.ignore_regex = None
        self.groups = None
        self.mount_point = None
        self.path = None
        self.port = None
        self.lookup = None
        self.line_skip = None
        self.delimit_regex = None
        self.record_count = 0
        self.scored = False
        self.__dict__.update(kwargs)

    def values(self):
        exclude = ['data', 'adict', 'nitro','kwargs']
        return [val for key, val in self.__dict__.items()
                    if not key.startswith('_')
                    if key not in exclude]

    def add_values(self, values):
        """
        Add values to static watchlist.
        Args:
            values (list): list of values
        """
        self.nitro.request('add_watchlist_values', watchlist=self['id'], values=values)

    def data_from_id(self, id):
        """
        Retrieve watchlist details for ID.
        Args:
            id (str): watchlist ID
        """
        info=self.nitro.request('get_watchlist_details', id=id)
        return info

    def load_details(self):
        """

        """
        the_id = self.data['id']
        self.data.update(self.data_from_id(the_id))
        self.data['id']=the_id

    def load_values(self, count=50):
        """
        Not properly tested yet.
        """
        self.data['values']=self.nitro.request('get_watchlist_values', id=self.data['id'], pos=0, count=count)

