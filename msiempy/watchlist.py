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
        self.nitro.request('add_watchlist', name=name, wl_type=wl_type)

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

