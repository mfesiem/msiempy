import abc
import collections
import json
import tqdm
import copy
import prettytable
import datetime
import logging
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
            alist=[]
        if isinstance(alist , (list, Manager)):
            collections.UserList.__init__(
                self, [Item(adict=item) for item in alist if isinstance(item, (dict, Item))])
        else :
            raise ValueError('Manager can only be initiated based on a list')

    @property
    def text(self):
        """
        Returns a nice string table made with prettytable.
        
        """
        table = prettytable.PrettyTable()
        fields=set()

        for item in self.data :
            if item is not None :
                fields=fields.union(dict(item).keys())
            else :
                log.warning('Having trouble with listing dicts')

        fields=sorted(fields)
        table.field_names=fields

        for item in self.data :
            if isinstance(item, NitroObject):
                for key in fields :
                    if key not in item :
                        item[key]='-'
                table.add_row([str(item[field]) for field in fields])

        return table.get_string()

    @property
    def json(self):
        return(json.dumps([dict(item) for item in self.data], indent=4, cls=NitroObject.NitroJSONEncoder))

    def search(self, pattern=None, invert=False, match_prop='json'):
        """
        Return a list of elements that matches regex pattern
        See https://docs.python.org/3/library/re.html#re.Pattern.search
        """
        if isinstance(pattern, str):
            try :
                matching_items=list()
                for item in self.data :
                    if regex_match(pattern, getattr(item, match_prop)) is not invert :
                        matching_items.append(item)
                return Manager(alist=matching_items)

            except Exception as err:
                raise err
        elif pattern is None :
            return self
        else:
            raise ValueError('pattern must be str or None')

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
        for item in self.data :
            item.selected=False
        #self.perform(Item.action_unselect, '.*') : 

    def refresh(self):
        self.perform(Item.action_refresh)

    def perform(self, func, pattern=None, search=None, *args, **kwargs):
        """
        Wrapper arround executable and group of object.
        Will execute the callable on specfied data (by `pattern`) and return a list of results

            Params
            ======
            func : callable stateless function
            if pattern stays None, will perform the action on the seleted rows,
                if no rows are selected, wil perform on all rows
            pattern can be :
                - string regex pattern match using search
                - a child Item object
                - a Manager(list) of Item(dict)
                - a list of lists of dict
                    However, only list of dict can be passed if asynch=True
                - Manager.SELECTED
            search : dict passed as extra arguments to search method
                i.e :
                    {invert=False, match_func='json'} or 
                    {time_range='CUSTOM', start_time='2019', end_time='2020'}
            
            confirm : will ask interactively confirmation (1)
            asynch : execute the task asynchronously with NitroSession executor (1)
            progress : to show progress bar with ETA (tqdm) (1)

            (1): passed as *args, **kwargs

        Returns a list of returned results
        """
        #if confirm : self.__ask(func, pattern)
        
        # If pattern is left None, apply the action to everything
        if pattern is None :
            return self.perform_static(func, 
                list(self), *args, **kwargs)

        #Pattern is a string
        if isinstance(pattern, str) :

            # Apply the action to selected items
            if pattern == self.SELECTED :
                return self.perform_static(func, 
                    self.selected_items,
                    *args, **kwargs)
            else:
                # Regex search when pattern is String.
                # search method returns a list 
                return self.perform_static(
                    func,
                    self.search(pattern, **(search if search is not None else {})),
                    *args, **kwargs)

        # Else, data is probably passed
        return self.perform_static(func, pattern,
                *args, **kwargs)

    @staticmethod
    def __ask(func, data):
        """
        Ask user inut to confirm the calling of `func` on `data`.
        """
        if not 'y' in input('Are you sure you want to do this '+str(func)+' on '+
        ('\n'+str(data) if data is not None else 'all data')+'? [y/n]: '):
            raise InterruptedError

    @staticmethod
    def perform_static(func, data, confirm=False, asynch=False, progress=False):
        """
        Static helper perform method
            confirm : will ask interactively confirmation
            asynch : execute the task asynchronously with
                NitroSession asynchronous executor
            progress : to show progress bar with ETA (tqdm)

        Important data type note :
            If data is a dict, Item or Manager : The callable will be execute on the obect itself.
            If data is a list, The callable will be execute on list's items.
        """
        log.debug('Calling perform func='+str(func)+' with pattern :'+str(data)[:100]+'... confirm='+str(confirm)+' asynch='+str(asynch)+' progress='+str(progress))

        if not callable(func) :
            raise ValueError('func must be callable')

        if not isinstance(data, (list, dict, Manager, Item)):
            raise ValueError('Datalist can only be : (list, dict, Manager, Item) not '+str(type(data)))

        if confirm : Manager.__ask(func, data)
    
        # The acual object last Recusion +0
        if isinstance(data, (dict, Item, Manager)):
            return(func(data))
    
        # A list of data is passed to perform()
        #   this includes the possibility of being a Manager object
        #   If iterative mode (default) : iterates
        #   If asynch : use executor
        if isinstance(data, (list, )):
                returned=list()

                if asynch == True :

                    #Throws error if recursive asynchronous jobs are requested
                    if any([not isinstance(data, (dict, Item, Manager)) for data in data]):
                        raise ValueError('''recursive asynchronous jobs are not supported. 
                        data list can only contains dict or Item obects if asynch=True''')

                    else:
                        if progress==True:
                            returned=list(tqdm.tqdm(NitroSession().executor.map(
                                func, data), desc='Loading...', total=len(data)))
                        else:
                            returned=list(NitroSession().executor.map(
                                func, data))
                else :
                    if progress==True:
                        data=tqdm.tqdm(data, desc='Loading...', total=len(data))

                    for index_or_item in data:
                        returned.append(func(index_or_item))

                return(returned)

    @property
    def selected_items(self):
        return(Manager(alist=[item for item in self.data if item.selected]))