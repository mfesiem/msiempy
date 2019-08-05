# -*- coding: utf-8 -*-
"""Provide whatchlist management."""

import logging
import collections
log = logging.getLogger('msiempy')
from . import NitroDict, NitroList

class WatchlistManager(NitroList):

    def __init__(self, *args, **kwargs):
        """

        """
        super().__init__(*args, **kwargs)
        self.data=self.nitro.request('get_watchlists_no_filters', hidden=False, dynamic=False, writeOnly=False, indexedOnly=False)

        #Casting all data to Watchlist objects, better way to do it ?
        collections.UserList.__init__(self, [Watchlist(adict=item) for item in self.data if isinstance(item, (dict, NitroDict))])

    def load_details(self):
        """
        
        """
        self.perform(Watchlist.load_details, asynch=False, progress=True)


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
        
        """
        self.nitro.request('add_watchlist_values', watchlist=self['id'], values=values)

    def data_from_id(self, id):
        """
        
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

