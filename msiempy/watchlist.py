# -*- coding: utf-8 -*-
"""Watchlist module offers a whatchlist management."""

import logging
import collections
log = logging.getLogger('msiempy')
from . import NitroDict, NitroList

class WatchlistManager(NitroList):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data=self.nitro.request('get_watchlists_no_filters', hidden=False, dynamic=False, writeOnly=False, indexedOnly=False)

        #Casting all data to Watchlist objects, better way to do it ?
        collections.UserList.__init__(self, [Watchlist(adict=item) for item in self.data if isinstance(item, (dict, NitroDict))])

    def load_details(self):
        self.perform(Watchlist.load_details, asynch=False, progress=True)


class Watchlist(NitroDict):
    """

    Complete list of watchlist fields (not values) once load with load_details()
    Dict keys :
        name: The name of the watchlist
        type: The watchlist type
        customType: The watchlist custom type (custom field)
        dynamic: Whether this watchlist is dynamic
        hidden:  Whether this watchlist is hidden
        scored: Whether this watchlist has a scoring component (GTI for example)
        valueCount: The number of values in this watchlist
        active: Whether this watchlist is a active
        errorMsg: The error message, if there is one associated with this watchlist
        source: source
        id: The id of the watchlist
        search: A regular expression, if applicable to the type of data source
        updateType: If dynamic is true, the type of update frequency (hourly, weekly, etc)
            Accepted Values:
            EVERY_SO_MANY_MINUTES
            HOURLY_AT_SPECIFIED_MINUTE
            DAILY_AT_SPECIFIED_TIME
            WEEKLY_AT_SPECIFIED_DAYTIME
            MONTHLY_AT_SPECIFIED_DAYTIME
        updateDay: The day the watchlist should be updated, if applicable. This value will either be the day of the week (1-7, corresponding to Sunday to Saturday), or the day of the month depending on the update type.
        updateMin: If dynamic is true and a minute field is applicable to the update frequency, this will hold the minute of either the hour or day depending on updateType.
        age: The age of the watchlist values in milliseconds
        ipsid: ipsid
        recordCount: The number of records in the watchlist
        valueFile: valueFile The file that can be obtained with a call to sysGetWatchlistValues containing all of the watchlist values
        dbUrl: If an enrichment source is being set up for the watchlist, this should hold the database URL
        mountPoint: If an enrichment source is being set up for the watchlist, this would hold the mount point if applicable. See product documentation on enrichment settings for more details.
        path: If the watchlist is populated from an enrichment source, this will hold the enrichment path setting. See the enrichment configuration documentation for more details on this setting.
        port: If the watchlist is populated from an enrichment source, this will hold the enrichment port setting. See the enrichment configuration documentation for more details on this setting.
        username: If the watchlist is populated from an enrichment source, this will hold the enrichment username setting. See the enrichment configuration documentation for more details on this setting.
        password: If the watchlist is populated from an enrichment source, this will hold the enrichment password setting. See the enrichment configuration documentation for more details on this setting.
        query: If the watchlist is populated from an enrichment source, this will hold the enrichment query setting. See the enrichment configuration documentation for more details on this setting.
        lookup: If the watchlist is populated from an enrichment source, this will hold the enrichment lookup setting. See the enrichment configuration documentation for more details on this setting.
        enabled: Whether the watchlist is enabled
        jobTrackerURL: If the watchlist is populated from an enrichment source, this will hold the enrichment Job Tracker URL setting. See the enrichment configuration documentation for more details on this setting.
        jobTrackerPort: If the watchlist is populated from an enrichment source, this will hold the enrichment Job Tracker Port setting. See the enrichment configuration documentation for more details on this setting.
        postArgs: If the watchlist is populated from an enrichment source, this will hold the enrichment Post Argument setting. See the enrichment configuration documentation for more details on this setting.
        sSLCheck: If the watchlist is populated from an enrichment source, this will hold the enrichment SSL Check setting. See the enrichment configuration documentation for more details on this setting.
        ignoreRegex: If the watchlist is populated from an enrichment source, this will hold the enrichment Ignore RegEx setting. See the enrichment configuration documentation for more details on this setting.
        method: If the watchlist is populated from an enrichment source, this will hold the enrichment method setting. See the enrichment configuration documentation for more details on this setting.
        matchRegex: If the watchlist is populated from an enrichment source, this will hold the enrichment match regex setting. See the enrichment configuration documentation for more details on this setting.
        lineSkip: If the watchlist is populated from an enrichment source, this will hold the enrichment line skip setting. See the enrichment configuration documentation for more details on this setting.
        delimitRegex: If the watchlist is populated from an enrichment source, this will hold the enrichment delimit regex setting. See the enrichment configuration documentation for more details on this setting.
        groups: If the watchlist is populated from an enrichment source, this will hold the enrichment groups setting. See the enrichment configuration documentation for more details on this setting.
        values: values
    
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def add_values(self, values):
        self.nitro.request('add_watchlist_values', watchlist=self['id'], values=values)

    def data_from_id(self, id):
        info=self.nitro.request('get_watchlist_details', id=id)
        return info

    def load_details(self):
        the_id = self.data['id']
        self.data.update(self.data_from_id(the_id))
        self.data['id']=the_id

    def load_values(self, count=50):
        """
        Not properly tested yet.
        """
        self.data['values']=self.nitro.request('get_watchlist_values', id=self.data['id'], pos=0, count=count)

