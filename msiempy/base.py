import abc
import collections
import json
import tqdm
import copy
import csv
import prettytable
import datetime
import functools
import logging
import requests
log = logging.getLogger('msiempy')

from .session import NitroSession
from .error import NitroError
from .utils import regex_match

class NitroObject(abc.ABC):
    """
    Base class for all nitro objects. All objects have a reference the single 
    NitroSession object that handle the esm requests
    """

    class NitroJSONEncoder(json.JSONEncoder):
        """
        Custom JSON encoder that will use the approprtiate propertie depending of the type of NitroObject.
        #TODO return meta info about the Manager. Maybe create a section `manager` and `data`.
        #TODO support json json dumping of QueryFilers, may be by making them inherits from Item.
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
        """
        self.nitro.request('esm-get-times')
        """
        self.nitro=NitroSession()

    def __str__(self):
        return self.text

    def __repr__(self):
        return self.json

    @abc.abstractproperty
    def text(self):
        """
        Returns str
        """
        pass

    @abc.abstractproperty
    def json(self):
        """
        Returns json representation
        """
        pass

    @abc.abstractmethod
    def refresh(self):
        """
        Refresh the state of the object
        """
        pass

    @staticmethod
    def action_refresh(ntiro_object):
        """
        Refrech callable to use with perform()
        """
        return(ntiro_object.refresh())

class Item(collections.UserDict, NitroObject):
    """
    Base class that represent any SIEM data that can be represented as a item of a manager.
    Exemple : Event, Alarm, etc...
    Inherits from dict
    """
    def __init__(self, adict=None):
        NitroObject.__init__(self)
        collections.UserDict.__init__(self, adict)
        
        for key in self.data :
            if isinstance(self.data[key], list):
                self.data[key]=Manager(alist=self.data[key])
                
        self.selected=False

    @property
    def json(self):
        return(json.dumps(dict(self), indent=4, cls=NitroObject.NitroJSONEncoder))

    @property
    def text(self):
        return(', '.join([str(val) for val in self.values()]))

    def refresh(self):
        log.debug('Refreshing item :'+str(self))

    '''This code has been commented cause it adds unecessary complexity.
    But it's a good example of how we could perform() method to do anything

    def select(self):
        self.selected=False

    def unselect(self):
        self.selected=True

    @staticmethod
    def action_select(item):
        item.select()

    @staticmethod
    def action_unselect(item):
        item.unselect()'''

class Manager(collections.UserList, NitroObject):
    """
    Base class for Managers objects. 
    Inherits from list
    """

    SELECTED='b8c0a7c5b307eeee30039343e6f23e9e4f1d325bbc2ffaf1c2b7b583af160124'
    """
    Random constant represents all selected items to avoid regex matching interference.
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
                self, [Item(adict=item) for item in alist if isinstance(item, (dict, Item))]
                )
        else :
            raise ValueError('Manager can only be initiated based on a list')

    @property
    def table_colums(self):            
        return []

    def _norm_dicts(self):
        """
        Internal method
        all dict should have the same set of keys
        Creating keys in dicts
        """
        for item in self.data :
            if isinstance(item, NitroObject):
                for key in self.keys :
                    if key not in item :
                        item[key]=None

    @property
    def keys(self):
        #Unique set of keys for all dict
        #If new fields are added it won't show on text repr. Only json.
        keys=set()
        #Normalizing the list of dict
        #Finding the unique set
        for item in self.data :
            if item is not None :
                keys=keys.union(dict(item).keys())
            else :
                log.warning('Having trouble with listing dicts')
        return keys

    @property
    def text(self):#, columns=None):
        """
        Returns a nice string table made with prettytable.
        It's an expesive thing to do on big ammount of data
        """
        table = prettytable.PrettyTable()
        fields=sorted(self.keys)
        table.field_names=fields
        self._norm_dicts()
        [table.add_row([str(item[field]) for field in fields]) for item in self.data]
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
        return text
        

    @property
    def json(self):
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
                if regex_match(apattern, getattr(item, match_prop)) is not invert :
                    matching_items.append(item)
            log.debug("You're search returned {} rows : {}".format(
                len(matching_items),
                str(matching_items)[:100]+'...'))
            #Apply AND reccursively
            return Manager(alist=matching_items).search(*pattern, invert=invert, match_prop=match_prop)
        else:
            raise ValueError('pattern must be str')

        

    ''' This code has been commented cause it adds unecessary complexity.
    But it's a good example of how we could perform() method to do anything

    def select(self, data_or_pattern, **search):
        """
        Select the rows that match the pattern.
        The patterm could be a index, list of index or list of rows
        """
        self.perform(Item.action_select, data_or_pattern, **search)

    def unselect(self, data_or_pattern, **search):
        """
        Unselect the rows that match the pattern.
        The patterm could be a index, list of index or list of rows
        """
        self.perform(Item.action_unselect, data_or_pattern, **search)
        '''
    
    def clear(self):
        """
        Unselect all items.
        """
        for item in self.data :
            item.selected=False
        #self.perform(Item.action_unselect, '.*') : 

    def refresh(self):
        """
        Execute refresh function on all items.
        """
        self.perform(Item.action_refresh)

    def perform(self, func, data=None, func_args=None, confirm=False, asynch=False, progress=False, message=None ):
        """
        Wrapper arround executable and the data list of Manager object.
        Will execute the callable the local manager data list.

            Params
            ======
            func : callable stateless function
                funs is going to be called like func(item, **func_args) on all items in data patern
            if data stays None, will perform the action on all rows, else it will perfom the action on the data list
            func_args : dict that will be passed by default to func in all calls
            confirm : will ask interactively confirmation 
            asynch : execute the task asynchronously with NitroSession executor 
            progress : to show progress bar with ETA (tqdm) 
            message : To show to the user

        Returns a list of returned results
        """

        log.debug('Calling perform func='+str(func)+
            ' data='+str(data)[:100]+
            ' func_args='+str(func_args)+
            ' confirm='+str(confirm)+
            ' asynch='+str(asynch)+
            ' progress='+str(progress))

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
        #The message will appear on loading bar if progress is True
        if progress is True :
            tqdm_args=dict(desc='Loading...', total=len(elements))
        if message is not None:
            log.info(message)
            tqdm_args['desc']=message

        

        #Runs the callable on list on executor or by iterating
        if asynch == True :
            
            if progress==True:
                #Need to call tqdm to have better support for concurrent futures executor
                # tqdm would load the whole bar intantaneously and not wait until the callable func returns. 
                returned=list(tqdm.tqdm(self.nitro.executor.map(
                    func, elements), **tqdm_args))
            else:
                log.info()
                returned=list(self.nitro.executor.map(
                    func, elements))
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

    @property
    def selected_items(self):
        """
        Selected items only.
        Returns a Manager
        """
        return(Manager(alist=[item for item in self.data if item.selected]))