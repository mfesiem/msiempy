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

    def __repr__(self):
        return self.data.__repr__()
    
    def __iter__(self):
        for data in self.data:
            yield data

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
        Load Watchlist details.
        """
        self.data.update(self.data_from_id(self.data['id']))

    def load_values(self):
        """
        Load Watchlist values.
        """
        wl_details = self.nitro.request('get_watchlist_values', id=self.data['id'])

        try:
            file = wl_details['WLVFILE']
        except KeyError:
            print('ESM Error: Is watchlist valid?')

        pos = 0
        nbytes = 0
        resp = self.nitro.request('get_rfile2', ftoken=file, pos=pos, nbytes=nbytes)

        if resp['FSIZE'] == resp['BREAD']:
            self.data['values'] = resp['DATA'].split('\n')
            self.nitro.request('del_rfile', ftoken=file)
            return

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
        self.data['values'] = ''.join(data).split('\n')
        resp = self.nitro.request('del_rfile', ftoken=file)