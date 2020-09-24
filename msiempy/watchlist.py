# -*- coding: utf-8 -*-
"""Provide watchlist management."""

import logging
import collections

log = logging.getLogger("msiempy")

from .core import NitroDict, NitroList


class WatchlistManager(NitroList):
    """
    List-Like object.
    Summary of ESM watchlists.

    Example:
    ```
    wlman = WatchlistManager()
    for wl in wlman:
        if wl['name'] == 'IPs-To-Block-On-IPS-24hrs': break
    wl.add_values(['1.1.1.2', '2.2.2.1', '3.3.3.1'])
    ```

    """

    def __init__(self, *args, **kwargs):
        """
        Initialize the watchlist manager.
        """
        super().__init__(*args, **kwargs)
        self.get_watchlist_summary()

    def get_watchlist_summary(self):
        """
        Loads the watchlist summary.
        """
        self.data = self.nitro.request(
            "get_watchlists_no_filters",
            hidden=False,
            dynamic=False,
            writeOnly=False,
            indexedOnly=False,
        )

        # Casting all data to Watchlist objects, better way to do it ?
        collections.UserList.__init__(
            self,
            [
                Watchlist(adict=item)
                for item in self.data
                if isinstance(item, (dict, NitroDict))
            ],
        )

    def load_details(self):
        """
        Load the details of existing watchlists.
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

        Arguments:

        - `name` (`str`): Name of the watchlist.
        - `wl_type` (`str`): Watchlist data type.
        Get the list of types with: `msiempy.watchlist.WatchlistManager.get_wl_types`.
        Most common types are: `IPAddress`,
                                `Hash`,
                                `SHA1`,
                                `DSIDSigID`,
                                `Port`,
                                `MacAddress`,
                                `NormID`,
                                `AppID`,
                                `CommandID`,
                                `DomainID`,
                                `HostID`,
                                `ObjectID`,
                                `Filename`,
                                `File_Hash`
        """
        for wl in self.data:
            if wl.get("name") == name:
                logging.error("Cannot add: {} watchlist already exists.".format(name))
                return
        self.nitro.request("add_watchlist", name=name, wl_type=wl_type)
        self.refresh()

    def remove(self, wl_id_list):
        """
        Remove watchlist(s).

        Arguments:

        - `wl_ids` (`list`): list of watchlist IDs. Example: `[1, 2, 3]`.
        """
        self.nitro.request("remove_watchlists", wl_id_list=wl_id_list)

    def get_wl_types(self):
        """
        Get a list of watchlist types.
        Returns: `list` of watchlist types.
        """
        return self.nitro.request("get_wl_types")


class Watchlist(NitroDict):
    """
    Dict-Like object.
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

    Arguments:

    - `adict`: Watchlist parameters
    - `id`: The watchlist ID to instanciate. Will load informations


    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def add_values(self, values):
        """
        Add values to static watchlist.

        Arguments:

        - `values` (`list`): list of values
        """
        self.nitro.request("add_watchlist_values", watchlist=self["id"], values=values)

    def remove_values(self, values):
        """
        Remove values from static watchlist.

        Arguments:

        - `values` (`list`): list of values
        """
        self.nitro.request(
            "remove_watchlist_values", watchlist=self["id"], values=values
        )

    def data_from_id(self, id):
        """
        Retrieve watchlist details for ID.

        Arguments:

        - `id` (`str`): watchlist ID
        """
        info = self.nitro.request("get_watchlist_details", id=id)
        return info

    def load_details(self):
        """
        Load Watchlist details.
        """
        self.data.update(self.data_from_id(self.data["id"]))

    def refresh(self):
        """Load Watchlist details."""
        self.load_details()

    def load_values(self):
        """
        Load Watchlist values.
        Raises: `KeyError` if watchlist invalid.
        """
        wl_details = self.nitro.request("get_watchlist_values", id=self.data["id"])

        try:
            file = wl_details["WLVFILE"]
        except KeyError:
            log.error("Is watchlist valid? ({})".format(str(self)))
            raise
        data = self.nitro.get_internal_file(file)
        self.data["values"] = "".join(data).split("\n")

    def get_id(self):
        """
        Returns the Watchlist ID.
        """
        return self["id"]
