"""Basics of msiempy. 2 main type of classes are offered in this API : lists and dicts.
Managers are lists and Items are dicts.
"""

import abc
import collections
import json
import tqdm
import copy
import csv
import concurrent.futures
import prettytable
from prettytable import MSWORD_FRIENDLY
import datetime
import functools
import logging
import textwrap
import requests
log = logging.getLogger('msiempy')

from .session import NitroSession
from .error import NitroError
from .utils import regex_match

class NitroObject(abc.ABC):
    """
    Base class for all nitro objects. All objects have a reference the single
    NitroSession object that handle the esm requests.
    """

    class NitroJSONEncoder(json.JSONEncoder):
        """
        Custom JSON encoder that will use the approprtiate propertie depending of the type of NitroObject.
        TODO return meta info about the Manager. Maybe create a section `manager` and `data`.
        TODO support json json dumping of QueryFilers, may be by making them inherits from Item.
        """
        def default(self, obj): # pylint: disable=E0202
            if isinstance(obj,(Item, Manager)):
                return obj.data
            #elif isinstance(obj, (QueryFilter)):
                #return obj.config_dict
            else:
                return json.JSONEncoder.default(self, obj) 

    @abc.abstractmethod
    def __init__(self):
        """Creates the object session.
        """
        self.nitro=NitroSession()

    def __str__(self):
        """
        str(obj) -> return text string.
        Can be a table if the object is a Manager.
        """
        return self.text

    def __repr__(self):
        """
        repr(obj) -> return json string.
        """
        return self.json

    @abc.abstractproperty
    def text(self):
        """
        Returns printable string.
        """
        pass

    @abc.abstractproperty
    def json(self):
        """
        Returns json string representation.
        """
        pass

    @abc.abstractmethod
    def refresh(self):
        """
        Refresh the state of the object.
        """
        pass

class Item(collections.UserDict, NitroObject):
    """
    Base class that represent any SIEM data that can be represented as a item of a manager.
    Exemple : Event, Alarm, etc...
    Inherits from dict.
    """
    def __init__(self, adict=None, id=None):
        """
        Initiate the NitroObject and UserDict objects, load the data if id is specified, use adict agument 
        and update dict values accordingly.
        """
        NitroObject.__init__(self)
        collections.UserDict.__init__(self, adict)
        
        if id != None :
            self.data=self.data_from_id(id)

        if isinstance(adict, dict):
            self.data=adict

        for key in self.data :
            if isinstance(self.data[key], list):
                self.data[key]=Manager(alist=self.data[key])

    @property
    def json(self):
        """JSON representation of a item. Basic dict.
        """
        return(json.dumps(dict(self), indent=4, cls=NitroObject.NitroJSONEncoder))

    @property
    def text(self):
        """A list of values. Not titles.
        """
        return(', '.join([str(val) for val in self.values()]))

    def refresh(self):
        """Not implemented here
        """
        log.debug('NOT Refreshing item :'+str(self)+' '+str(NotImplementedError()))

    @abc.abstractmethod
    def data_from_id(self, id):
        """This method figured out the way to retreive the item infos from an id.
        """
        pass

class Manager(collections.UserList, NitroObject):
    """
    Base class for Managers objects. 
    Inherits from list
    """

    def __init__(self, alist=None):
        """
        Ignore nested lists. Meaning that if alist if a list of lists 
            it will we be ignored.
        Nevertheless, if a list is present as a key value in a dict, 
            it will be added as such.
        """
        NitroObject.__init__(self)
        if alist is None:
            collections.UserList.__init__(self, [])
        
        elif isinstance(alist , (list, Manager)):
            collections.UserList.__init__(
                self, alist #[Item(adict=item) for item in alist if isinstance(item, (dict, Item))] 
                #Can't instanciate Item, so Concrete classes has to cast the items afterwards
                )
        else :
            raise ValueError('Manager can only be initiated based on a list')

    @property
    def table_colums(self):
        """Return the list of columns the table representation will have. This attribute is designed to overwritten.
        """            
        return []

    def _norm_dicts(self):
        """
        Internal method
        all dict should have the same set of keys
        Creating keys in dicts
        """
        for item in self.data :
            if isinstance(item, (dict, Item)):
                for key in self.keys :
                    if key not in item :
                        item[key]=None

    @property
    def keys(self):
        """Set of keys for all dict
        """
        #If new fields are added it won't show on text repr. Only json.
        
        manager_keys=set()
        for item in self.data:
            if isinstance(item, (dict,Item)):
                manager_keys.update(item.keys())

        return manager_keys


    def get_text(self, compact=False, fields=None, max_column_width=120):
        """
        Return a acsii table string representation of the manager list
            compact : Returns a nice string table made with prettytable, else an '|' separated list.
            fields : list of fields you want in the table
                is None : default fields are returned by .keys attribute and sorted.
            max_column_width when using prettytable (not compact)

        It's an expesive thing to do on big ammount of data !
        """
        
        if not fields :
            fields=sorted(self.keys)

        if len(self) == 0 :
            return('The list is empty')

        if not compact : #Table
            table = prettytable.PrettyTable()
            table.set_style(MSWORD_FRIENDLY)
            table.field_names=fields
            self._norm_dicts()

            for item in self.data:
                if isinstance(item, (dict, Item)):
                    table.add_row(['\n'.join(textwrap.wrap(str(item[field]), width=max_column_width))
                        if not isinstance(item[field], Manager)
                        else item[field].get_text() for field in fields])
                else : log.warning("Unnapropriate list element type, doesn't show on the list : {}".format(str(item)))

            if len(self.table_colums) >0 :
                try :
                    text =table.get_string(fields=self.table_colums)
                except Exception as err :
                    if "Invalid field name" in str(err):
                        text=table.get_string()
                        log.warning("Inconsistent manager state, some fields aren't present {}".format(str(err)))
                    else :
                        raise
            else: 
                text=table.get_string()

        elif compact is True :
            text='|_'
            for field in fields :
                text+=field
                text+='_|_'
            text=text[0:len(text)-1]
            text+='\n'
            for item in self.data:
                if isinstance(item, (dict, Item)):
                    text+='| '
                    for field in fields :
                        if isinstance(item[field], Manager):
                            text+=item[field].get_text(compact=True)
                        else:
                            text+=(str(item[field]))
                            text+=' | '
                    text=text[0:len(text)-1]
                else : log.warning("Unnapropriate list element type, doesn't show on the list : {}".format(str(item)))
                    #text+=textwrap.wrap(str(item),width=max_column_width)
                text+='\n'
            text=text[0:len(text)-1]
        return text



    @property
    def text(self):
        """The text properti is a shorcut to get_text() with no arguments.
        """
        return self.get_text()
        
    @property
    def json(self):
        """Dumps a JSON list of dicts.
        """
        return(json.dumps([dict(item) for item in self.data], indent=4, cls=NitroObject.NitroJSONEncoder))

    def search(self, *pattern, invert=False, match_prop='json'):
        """
        Return a list of elements that matches regex patterns.
        Patterns are applied one after another. It's a logic AND.
        Use `|` inside patterns to search with logic OR.
        This method will return a new Manager with matching data. Items in the returned Manager do not
        references the items in the original Manager.

        If you wish to apply more specific filters to Manager list, please
        use filter(), list comprehension, or other filtering method.
            i.e. : `[item for item in manager if item['cost'] > 50]`

        More on regex https://docs.python.org/3/library/re.html#re.Pattern.search
        """
        if pattern is None :
            return self
        elif len(pattern) == 0 :
            return self
        else :
            pattern=list(pattern)
            apattern=pattern.pop()
        
        matching_items=list()
        
        if isinstance(apattern, str):
            for item in self.data :
                if regex_match(apattern, getattr(item, match_prop) if isinstance(item, Item) else str(item)) is not invert :
                    matching_items.append(item)
            log.debug("You're search returned {} rows : {}".format(
                len(matching_items),
                str(matching_items)[:100]+'...'))
            #Apply AND reccursively
            return Manager(alist=matching_items).search(*pattern, invert=invert, match_prop=match_prop)
        else:
            raise ValueError('pattern must be str')

    def refresh(self):
        """
        Execute refresh function on all items.
        """
        log.warning("The function Manager.refresh hasn't been correctly tested")
        self.perform(Item.refresh)

    def perform(self, func, data=None, func_args=None, confirm=False, asynch=False,  workers=None , progress=False, message=None):
        """
        Wrapper arround executable and the data list of Manager object.
        Will execute the callable the local manager data list.

            Params
            
            func : callable stateless function
                funs is going to be called like func(item, **func_args) on all items in data patern
            if data stays None, will perform the action on all rows, else it will perfom the action on the data list
            func_args : dict that will be passed by default to func in all calls
            confirm : will ask interactively confirmation 
            asynch : execute the task asynchronously with NitroSession executor
            workers : mandatory if asynch is true
            progress : to show progress bar with ETA (tqdm) 
            message : To show to the user

        Returns a list of returned results
        """

        log.debug('Calling perform func='+str(func)+
            ' data='+str(data)[:100]+
            ' func_args='+str(func_args)+
            ' confirm='+str(confirm)+
            ' asynch='+str(asynch)+
            ' workers='+str(workers)+
            ' progress='+str(progress)+
            ' message='+str(message))

        if not callable(func) :
            raise ValueError('func must be callable')

        #Confirming with user if asked
        if confirm : self._confirm_func(func, str(self))

        #Setting the arguments on the function
        func = functools.partial(func, **(func_args if func_args is not None else {}))
        
        #The data returned by function
        returned=list()

        #Usethe self contained data if not speficed otherwise
        elements=self.data
        if isinstance(data, list) and data is not None:
            elements=data
        else :
            AttributeError('data must be a list')

        #Printing message if specified.
        tqdm_args=dict()
        #The message will appear on loading bar if progress is True
        if progress is True :
            tqdm_args=dict(desc='Loading...', total=len(elements))
            if message is not None:
                tqdm_args['desc']=message

        

        #Runs the callable on list on executor or by iterating
        if asynch == True :
            if isinstance(workers, int) :
                if progress==True:
                    #Need to call tqdm to have better support for concurrent futures executor
                    # tqdm would load the whole bar intantaneously and not wait until the callable func returns. 
                    returned=list(tqdm.tqdm(concurrent.futures.ThreadPoolExecutor(
                    max_workers=workers ).map(
                        func, elements), **tqdm_args))
                else:
                    #log.info()
                    returned=list(concurrent.futures.ThreadPoolExecutor(
                    max_workers=workers ).map(
                        func, elements))
            else:
                raise AttributeError('When asynch == True : You must specify a integer value for workers')
        else :

            if progress==True:
                elements=tqdm.tqdm(elements, **tqdm_args)

            for index_or_item in elements:
                returned.append(func(index_or_item))

        return(returned)

    @staticmethod
    def _confirm_func(func, elements):
        """
        Ask user inut to confirm the calling of `func` on `elements`.
        """
        if not 'y' in input('Are you sure you want to do this '+str(func)+' on '+
        ('\n'+str(elements) if elements is not None else 'all elements')+'? [y/n]: '):
            raise InterruptedError("The action was cancelled by the user.")