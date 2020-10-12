# -*- coding: utf-8 -*-
"""
Base classes for SIEM interface objects and generic definitions.  
"""

import logging
import json
import abc
import collections

import json
import collections
import tqdm
import csv
import concurrent.futures
import prettytable
from prettytable import MSWORD_FRIENDLY
import functools
import textwrap
import logging
from io import StringIO

from .utils import regex_match
from .session import NitroSession

log = logging.getLogger("msiempy")


class NitroObject(abc.ABC):
    """
    Base class for all nitro objects. All objects have a reference to the single `msiempy.core.session.NitroSession` object that handle the esm requests.
    Creates the object session.
    """

    class NitroJSONEncoder(json.JSONEncoder):
        """
        Custom JSON encoder that will use the approprtiate propertie depending of the type of NitroObject.
        TODO support json json dumping of QueryFilers, may be by making them inherits from NitroDict.
        """

        def default(self, obj):  # pylint: disable=E0202
            if isinstance(obj, (NitroObject)):
                return obj.data
            else:
                return json.JSONEncoder.default(self, obj)

    def __init__(self):
        self.nitro = NitroSession()
        """
        `msiempy.core.session.NitroSession` object. Interface to the SIEM.
        """

    @abc.abstractproperty
    def text(self):
        """
        Returns printable string.
        Abstract declaration.
        """
        pass

    @abc.abstractproperty
    def json(self):
        """
        Returns json string representation.
        Abstract declaration.
        """

    @abc.abstractmethod
    def refresh(self):
        """
        Re-load the object.
        Abstract declaration.
        """
        pass


class NitroDict(collections.UserDict, NitroObject):
    """
    Dict-Like object (Base class) to represent SIEM data.
    Exemple : `Event`, `Alarm`, etc...

    This classe and subclasses fully implements `dict` interface and is suitable for dictionnary operations, see: https://docs.python.org/3/library/stdtypes.html#mapping-types-dict
    
    :ivar data: Underlying `dict` object
    """

    def __init__(self, adict=None, id=None):
        """
        Create a new dict item

        Arguments:
            - `adict`: dict object to wrap., typically received from the SIEM.
            - `id`: ESM obejct unique identifier. `Alert.IPSIDAlertID` for exemple. Load the data from the SIEM.

        Note:
            `NitroDict` is an abstract class and cannot be instanciated as is.  
        """
        NitroObject.__init__(self)
        collections.UserDict.__init__(self, adict)

        if adict:
            self.data = adict
        if id:
            self.data = self.data_from_id(id)

        for key in list(self):
            if isinstance(self[key], list):
                self[key] = NitroList(alist=self[key])

    def __str__(self):
        """str(obj) -> return text string."""
        return self.text

    def __repr__(self):
        """repr(obj) -> return json string."""
        return self.json

    @property
    def json(self):
        """JSON representation of a item"""
        return json.dumps(dict(self), indent=4, cls=NitroObject.NitroJSONEncoder)

    @property
    def text(self):
        """Text list of item's values"""
        return ", ".join([str(val) for val in self.values()])

    @abc.abstractmethod
    def data_from_id(id):
        """This method retreive the item infos from an object ID.
        Abstract declaration.
        """
        pass

    @abc.abstractmethod
    def get_id(self):
        """
        Return the object ID.
        Abstract definition.
        """

        pass


class NitroList(collections.UserList, NitroObject):
    """
    Base class for list objects.

    It offers search and other data list actions.

    This classe and subclasses fully implements `list` interface and is suitable for list operations, see: https://docs.python.org/3/library/stdtypes.html#sequence-types-list-tuple-range

    Concrete classes have to cast the list items in their `__init__` method !

    Subclassing requirements: Subclasses of UserList are expected to offer a constructor which can be called with either no arguments or one argument. List operations which return a new sequence attempt to create an instance of the actual implementation class. To do so, it assumes that the constructor can be called with a single parameter, which is a sequence object used as a data source.
    If a derived class does not wish to comply with this requirement, all of the special methods supported by this class will need to be overridden; please consult the sources for information about the methods which need to be provided in that case.
    See: https://docs.python.org/3.8/library/collections.html?highlight=userdict#userlist-objects

    :ivar data: Underlying `list` object
    """

    def __init__(self, alist=None):
        """
        Create a new list
        
        Arguments:
            - `alist`: list object to wrap.
        """
        NitroObject.__init__(self)
        if alist:
            collections.UserList.__init__(self, alist)
        else:
            collections.UserList.__init__(self, [])

    def __str__(self):
        """str(obj) -> return text string."""
        return "<{} containing {} elements, keys={}>".format(
            str(super()), len(list(self)), self.keys()
        )

    def keys(self):
        """List items keys. Every items should have the same set of keys."""
        # If new fields are added it won't show on text repr. Only json.
        manager_keys = set()
        for item in list(self):
            manager_keys.update(getattr(item, "keys", set)())
        return manager_keys

    def get_text(
        self,
        format="prettytable",
        fields=None,
        max_column_width=80,
        get_text_nest_attr={},
    ):
        """
        Return a csv or table string representation of the list

        Arguments:
            - `format` (`str`):
                - ``prettytable``: Returns a table generated by prettytable use ``MSWORD_FRIENDLY`` format.
                - ``csv``: Returns data with header and comma separated values.
            - `fields` (`lis[str]`): list of fields you want in the table. If `None` : default fields are returned by .keys attribute and sorted.
            - `max_column_width` (`int`): when using prettytable only
            - `get_text_nest_attr` (`dict`): attributes passed to the nested `msiempy.core.types.NitroList.get_text` elements if any. Useful to control events appearence.
        """

        text = str()

        if not fields:
            fields = sorted(self.keys())

        if format == "csv":
            file = StringIO()
            dw = csv.DictWriter(file, fields, extrasaction="ignore")
            dw.writeheader()
            dw.writerows(list(self))
            text = file.getvalue()

        elif format == "prettytable":
            table = prettytable.PrettyTable()
            table.set_style(MSWORD_FRIENDLY)

            table.field_names = fields

            for item in list(self):
                if isinstance(item, (dict, NitroDict)):
                    values = list()
                    for field in fields:
                        obj = None
                        try:
                            obj = item[field]
                        except KeyError:
                            pass

                        if isinstance(obj, NitroList):
                            values.append(obj.get_text(**get_text_nest_attr))
                        else:
                            values.append(
                                "\n".join(
                                    textwrap.wrap(str(obj), width=max_column_width)
                                )
                            )

                    table.add_row(values)

                else:
                    log.warning(
                        "Unnapropriate list element type, won't show on the prettytable : {}".format(
                            str(item)
                        )
                    )

            text = table.get_string()

        else:
            raise AttributeError(
                "Unknown `NitroList.get_text` format : {}. Accepted values are 'prettytable' or 'csv'.".format(
                    format
                )
            )

        return text

    @property
    def text(self):
        """Defaut table string, a shorcut to `get_text()` with no arguments."""
        return self.get_text()

    @property
    def json(self):
        """JSON list of dicts representing the list."""
        return json.dumps(
            [dict(item) for item in list(self)],
            indent=4,
            cls=NitroObject.NitroJSONEncoder,
        )

    def search(self, term, fields=None, invert=False):
        """
        Search elements in the list with a regex pattern

        Arguments:
            - `term` (`str`): String regex pattern to look for in the list items values. More on regex https://docs.python.org/3/library/re.html#re.Pattern.search
            - `invert` (`bool`): Weither or not to invert the search and return elements that doesn't not match search.
            - `fields` (`list[str]`): Dictionnary fields to consider in the search, all keys are considered by default.  Patterns are compared to `str` representation of values.  

        If you wish to apply non-regex filters to, use `filter()` or list comprehension::

            [e for e in events if int(e['severity']) > 50]
        
        Returns:
            List-Like object of matching items
        
        Exemple:
        
        >>> from msiempy import WatchlistManager
        >>> wl_list = WatchlistManager()
        >>> wl_ip_list = wl_list.search("IPAddress", fields=["type"])
        >>> print(len(wl_ip_list))
        2 # There is two "IPAddress" watchlists
        """
        if not term:
            raise ValueError("")

        if fields:
            if not isinstance(fields, list):
                fields = [fields]
        else:
            fields = self.keys()

        matching_items = list()

        if isinstance(term, str):

            for item in list(self):
                for f in fields:
                    if regex_match(term, str(item.get(f))) != invert:
                        matching_items.append(item)
                        break  # for f in fields

            log.debug(
                "You're search returned {} rows : {}".format(
                    len(matching_items), str(matching_items)[:200] + "..."
                )
            )

            return type(self)(matching_items) 
        
        else:
            raise ValueError("pattern must be str. Not {}".format(term))

    def refresh(self):
        """
        Execute refresh function on all items.
        """
        self.perform(NitroDict.refresh, message="Refreshing all items...")

    def perform(
        self,
        func,
        data=None,
        func_args=None,
        confirm=False,
        asynch=False,
        workers=None,
        progress=False,
        message=None,
    ):
        """
        Wrapper to execute a function on the list of elements

        Arguments:
            - `func` (`callable`): Function. `func` is going to be called like `func(item, **func_args)` on all items in data. 
            - `data` (`list`): Choose a custom list to execute the function on (Default value = `list(self)`)
            - `func_args` (`dict`): arguments that will be passed by default to `func` in all calls.
            - `confirm` (`bool`): will ask interactively confirmation.
            - `asynch` (`bool`): execute the task asynchronously with `concurrent.futures.ThreadPoolExecutor`. Carefull not to nest 2 asynchronous executions within eachother, it will be a mess.
            - `workers` (`int`): number of parrallel tasks, mandatory if asynch is true.
            - `progress` (`bool`): to show progress bar with ETA (`tqdm`).
            - `message` (`str`): To show to the user.

        This method is where the core of asynchronous tasks resides. `func` will be executed on all `data` elements.
        Basically, if `asynch==True`, will return::

            returned=list(concurrent.futures.ThreadPoolExecutor(
                        max_workers=workers ).map(
                            func, data))

        if `asynch==False`, will iterate and return::

            for index_or_item in data:
                returned.append(func(index_or_item))

        Returns:
            `list` of returned results.
        """

        log.debug(
            "Calling perform func="
            + str(func)
            + " data="
            + str(data)[:100]
            + " func_args="
            + str(func_args)
            + " confirm="
            + str(confirm)
            + " asynch="
            + str(asynch)
            + " workers="
            + str(workers)
            + " progress="
            + str(progress)
            + " message="
            + str(message)
        )

        if not callable(func):
            raise ValueError("func must be callable")

        # Confirming with user if asked
        if confirm:
            self._confirm_func(func, str(self))

        # Setting the arguments on the function
        func = functools.partial(func, **(func_args if func_args != None else {}))

        # The data returned by function
        returned = list()

        # Usethe self contained data if not speficed otherwise
        elements = list(self)
        if data:
            if isinstance(data, list):
                elements = data
            else:
                raise TypeError(
                    "data argument must be a list not {}".format(type(data))
                )

        # Printing message if specified.
        tqdm_args = dict()

        # The message will appear on loading bar if progress is True
        if progress is True:
            tqdm_args = dict(desc="Loading...", total=len(elements))
            if message != None:
                tqdm_args["desc"] = message
        elif message != None:
            log.info(message)

        # Runs the callable on list on executor or by iterating
        if asynch == True:
            if isinstance(workers, int):
                if progress == True:
                    if not self.nitro.config.quiet:
                        # Need to call tqdm to have better support for concurrent futures executor
                        # tqdm would load the whole bar intantaneously and not wait until the callable func returns.
                        returned = list(
                            tqdm.tqdm(
                                concurrent.futures.ThreadPoolExecutor(
                                    max_workers=workers
                                ).map(func, elements),
                                **tqdm_args
                            )
                        )
                    else:
                        returned = list(
                            concurrent.futures.ThreadPoolExecutor(
                                max_workers=workers
                            ).map(func, elements)
                        )
                else:
                    returned = list(
                        concurrent.futures.ThreadPoolExecutor(max_workers=workers).map(
                            func, elements
                        )
                    )
            else:
                raise AttributeError(
                    "When asynch == True : You must specify a integer value for workers"
                )
        else:

            if progress == True:
                if not self.nitro.config.quiet:
                    elements = tqdm.tqdm(elements, **tqdm_args)

            for index_or_item in elements:
                returned.append(func(index_or_item))

        return returned

    @staticmethod
    def _confirm_func(func, elements):
        """
        Ask user inut to confirm the calling of `func` on `elements`.
        """
        if not "y" in input(
            "Are you sure you want to do this "
            + str(func)
            + " on "
            + ("\n" + str(elements) if elements != None else "all elements")
            + "? [y/n]: "
        ):
            raise InterruptedError("The action was cancelled by the user.")
