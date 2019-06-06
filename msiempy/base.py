import abc
import collections
import json
import tqdm
import prettytable
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
        def default(self, obj): # pylint: disable=E0202
            if isinstance(obj,(Item, Manager)):
                return obj.data
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

    @abc.abstractproperty
    def text(self) -> str:
        pass

    @abc.abstractproperty
    def json(self) -> dict:
        pass

    @abc.abstractmethod
    def refresh(self) -> bool:
        pass

    @staticmethod
    def action_refresh(ntiro_object) -> bool:
        return(ntiro_object.refresh())

class Item(collections.UserDict, NitroObject):
    """
    Base class that represent any SIEM data that can be represented as a item of a manager.
    Exemple : Event, Alarm, etc...
    Inherits from dict
    """
    def __init__(self, other_dict=None):
        NitroObject.__init__(self)
        collections.UserDict.__init__(self, other_dict)
        
        for key in self.data :
            if isinstance(self.data[key], list):
                self.data[key]=Manager(self.data[key])
                
        self.selected=False

    @property
    def json(self) -> str:
        return(json.dumps(dict(self), indent=4, cls=NitroObject.NitroJSONEncoder))

    @property
    def text(self) -> str:
        return(repr(dict(self)))

    def refresh(self) -> bool:
        log.debug('Refreshing '+str(self))

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
    Just a random constant represents all the selectec items. Juste to make sure we don't interfer with regex matching
    """

    def __init__(self, other_list=None):
        """
        Ignore nested lists. Meaning that if other_list if a list of lists 
            it will we be ignored
        Nevertheless, if a list is present as a key valur in a dict, 
            it will be added as such
        """
        NitroObject.__init__(self)
        collections.UserList.__init__(
            self, [Item(item) for item in other_list if isinstance(item, (dict, Item))])

    @property
    def text(self):
        table = prettytable.PrettyTable()
        fields=set()

        for item in self.data :
            fields=fields.union(dict(item).keys())

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
    def json(self) -> str:
        return(json.dumps([dict(item) for item in self.data], indent=4, cls=NitroObject.NitroJSONEncoder))

    def search(self, pattern=None, invert=False, match_func='json') -> list:
        """
        Return a list of elements that matches regex pattern
        See https://docs.python.org/3/library/re.html#re.Pattern.search
        """
        if isinstance(pattern, str):
            try :
                matching_items=list()
                for item in self.data :
                    if regex_match(pattern, getattr(item, match_func)) is not invert :
                        matching_items.append(item)
                return Manager(matching_items)

            except Exception as err:
                raise NotImplementedError(str(err))
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
        self.perform(Item.action_refresh, '.*')

    def perform(self, func, pattern=None, search=None, *args, **kwargs) -> list:
        """
            func : callable stateless function
            if data_or_pattern stays None, will perform the action on the seleted rows,
                if no rows are selected, wil perform on all rows
            pattern can be :
                - string regex pattern match using search
                - a child Item object
                - a Manager(list) of Item(dict)
                - a list of lists of dict
                    However, only list of dict can be passed if asynch=True
                - Manager.SELECTED
            search : dict that will be passed as extra **arguments to search method
                i.e :
                    {invert=False, match_func='json'} or 
                    {time_range='CUSTOM', start_time='2019', end_time='2020'}
            confirm : will ask interactively confirmation
            asynch : execute the task asynchronously with NitroSession executor
            progress : to show progress bar with ETA (tqdm)
        """
        #if confirm : self.__ask(func, data_or_pattern)
        
        # If pattern is left None, apply the action to selected rows if any else everything
        # Recursion +1
        if pattern is None :
            return self.__perform(func, 
                self, *args, **kwargs)

        #pattern is a string
        if isinstance(pattern, str) :

            # Selected items only
            # +1 Recursion
            if pattern == self.SELECTED :
                return self.__perform(func, 
                    self.selected_items,
                    *args, **kwargs)
            else:
                # Regex search when pattern is String.
                # search method returns a list 
                # +1 Recursion
                return self.__perform(
                    func,
                    self.search(pattern, **(search if search is not None else {})),
                    *args, **kwargs)

        # If passed other object type 
        #   use static __perform directly
        return self.__perform(func,
                datalist=pattern,
                *args, **kwargs)

    @staticmethod
    def __ask(func, data):
        if not 'y' in input('Are you sure you want to do this '+str(func)+' on '+
        (str(data) if data is not None else 'all')+'? [y/n]: '):
            raise InterruptedError

    @staticmethod
    def __perform(func, datalist, confirm=False, asynch=False, progress=False, recursions=5, *args, **kwargs):
        """
        Static helper perform method
        """
        if confirm : Manager.__ask(func, datalist)

        if not callable(func) :
            raise ValueError('func must be callable')

        if not isinstance(datalist, (list, dict, Manager, Item)):
            raise ValueError('datalist can only be : (list, dict, Manager, Item) not '+str(type(datalist)))

        recursions-=1
        returned=list()

        log.debug('Calling perform func='+str(func)+' with pattern :'+str(datalist))

        #End of the recursion potential
        if recursions <= 0 :
            log.warning(RecursionError('''maximum perform recursion reached :/ 
                try a data structure more simple'''))
            return returned
    
        # A list of data is passed to perform()
        #   this includes the possibility of being a Manager object
        # +1 Recursion if iterative mode (default)
        # +0 Recursion if asynch : use executor
        if isinstance(datalist, (Manager, list)):

                if progress==True:
                    datalist=tqdm.tqdm(datalist)

                if asynch == True :

                    #Throws error if recursive asynchronous jobs are requested
                    if any([not isinstance(data, (dict, Item)) for data in datalist]):
                        raise ValueError('''recursive asynchronous jobs are not supported. 
                        datalist list can only contains dict or Item obects if asynch=True''')

                    else:
                        returned=list(NitroSession().executor.map(
                            func,
                            datalist))
                else :
                    for index_or_item in datalist:
                        returned.append(Manager.__perform(
                            func,
                            index_or_item,
                            recursions=recursions))

                return(returned)
        
        # The acual object last Recusion +0
        elif isinstance(datalist, (dict, Item)):
            return(func(datalist))


    @property
    def selected_items(self):
        return(Manager([item for item in self.data if item.selected]))

class QueryManager(Manager):
    """
    Base class for query based managers. QueryManager object can handle time_ranges.
    # the
    """

    def __init__(self, time_range=None, start_time=None, end_time=None, sub_query=0):
        super().__init__()

    def add_filter(self, filter):
        pass

    def clear_filters(self):
        pass 

    