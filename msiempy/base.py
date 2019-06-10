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
from .utils import regex_match, convert_to_time_obj, divide_times, format_esm_time, timerange_gettimes

class NitroObject(abc.ABC):
    """
    Base class for all nitro objects. All objects have a reference the single 
    NitroSession object that handle the esm requests
    """

    class NitroJSONEncoder(json.JSONEncoder):
        def default(self, obj): # pylint: disable=E0202
            if isinstance(obj,(Item, Manager)):
                return obj.data
            elif isinstance(obj, (QueryFilter)):
                return obj.config_dict
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
    def text(self):
        """
        Returns str
        """
        pass

    @abc.abstractproperty
    def json(self):
        """
        Returns json repr
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
    def __init__(self, other_dict=None):
        NitroObject.__init__(self)
        collections.UserDict.__init__(self, other_dict)
        
        for key in self.data :
            if isinstance(self.data[key], list):
                self.data[key]=Manager(self.data[key])
                
        self.selected=False

    @property
    def json(self):
        return(json.dumps(dict(self), indent=4, cls=NitroObject.NitroJSONEncoder))

    @property
    def text(self):
        return(repr(dict(self)))

    def refresh(self):
        log.debug('Refreshing '+str(NotImplementedError())+str(self))

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
                self, [Item(item) for item in alist if isinstance(item, (dict, Item))])
        else :
            raise ValueError('Manager can only be initiated based on a list')

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
    def json(self):
        return(json.dumps([dict(item) for item in self.data], indent=4, cls=NitroObject.NitroJSONEncoder))

    def search(self, pattern=None, invert=False, match_func='json'):
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
                return Manager(alist=matching_items)

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

    def perform(self, func, pattern=None, search=None, *args, **kwargs):
        """
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
        
        # If pattern is left None, apply the action to selected rows if any else everything
        if pattern is None :
            return self.perform_static(func, 
                self, *args, **kwargs)

        #Pattern is a string
        if isinstance(pattern, str) :

            # Selected items only
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

        # Else, data is probably passed,
        #   use static perform_static directly
        return self.perform_static(func,
                datalist=pattern,
                *args, **kwargs)

    @staticmethod
    def __ask(func, data):
        if not 'y' in input('Are you sure you want to do this '+str(func)+' on '+
        ('\n'+str(data) if data is not None else 'all')+'? [y/n]: '):
            raise InterruptedError

    @staticmethod
    def perform_static(func, datalist, confirm=False, asynch=False, progress=False):
        """
        Static helper perform method
            confirm : will ask interactively confirmation
            asynch : execute the task asynchronously with NitroSession executor
            progress : to show progress bar with ETA (tqdm)
        """
        log.debug('Calling perform func='+str(func)+' with pattern :'+str(datalist)+'confirm='+str(confirm)+' asynch='+str(asynch)+' progress='+str(progress))

        if not callable(func) :
            raise ValueError('func must be callable')

        if not isinstance(datalist, (list, dict, Manager, Item)):
            raise ValueError('Datalist can only be : (list, dict, Manager, Item) not '+str(type(datalist)))

        if confirm : Manager.__ask(func, datalist)
    
        # The acual object last Recusion +0
        if isinstance(datalist, (dict, Item, Manager)):
            return(func(datalist))
    
        # A list of data is passed to perform()
        #   this includes the possibility of being a Manager object
        # +0 Recursion if iterative mode (default) | iterates
        # +0 Recursion if asynch : use executor
        if isinstance(datalist, (list, )):
                returned=list()

                if progress==True:
                    datalist=tqdm.tqdm(datalist)

                if asynch == True :

                    #Throws error if recursive asynchronous jobs are requested
                    if any([not isinstance(data, (dict, Item, Manager)) for data in datalist]):
                        raise ValueError('''recursive asynchronous jobs are not supported. 
                        datalist list can only contains dict or Item obects if asynch=True''')

                    else:
                        returned=list(NitroSession().executor.map(
                            func, datalist))
                else :
                    for index_or_item in datalist:
                        returned.append(func(index_or_item))

                return(returned)

    @property
    def selected_items(self):
        return(Manager(alist=[item for item in self.data if item.selected]))

class QueryManager(Manager):
    """
    Base class for query based managers : AlarmManager, EventManager
    QueryManager object can handle time_ranges.
    """
    DEFAULT_TIME_RANGE="CURRENT_DAY"
    POSSIBLE_TIME_RANGE=[
            "CUSTOM",
            "LAST_MINUTE",
            "LAST_10_MINUTES",
            "LAST_30_MINUTES",
            "LAST_HOUR",
            "CURRENT_DAY",
            "PREVIOUS_DAY",
            "LAST_24_HOURS",
            "LAST_2_DAYS",
            "LAST_3_DAYS",
            "CURRENT_WEEK",
            "PREVIOUS_WEEK",
            "CURRENT_MONTH",
            "PREVIOUS_MONTH",
            "CURRENT_QUARTER",
            "PREVIOUS_QUARTER",
            "CURRENT_YEAR",
            "PREVIOUS_YEAR"
        ]

    def __init__(self, time_range=None, start_time=None, end_time=None, filters=None, 
        load_async=True, query_depth=0, split_strategy='delta', *arg, **kwargs):
        """
        Base class that handles the time ranges operations, loading data from the SIEM
        """

        super().__init__(*arg, **kwargs)

        self.nitro.config.default_rows #nb rows per request : eq limit/page_size
        self.nitro.config.max_rows #max nb rows 

        #Declaring attributes and types
        self._time_range=str()
        self._start_time=None
        self._end_time=None

        #self.filters=filters filter property setter should be called in the concrete class
        self.load_async=load_async

        if start_time is not None and end_time is not None :
            self.start_time=start_time
            self.end_time=end_time
        else :
            self.time_range=time_range

        self.load_async=load_async
        self.query_depth=query_depth
        self.split_strategy=split_strategy


    @property
    def time_range(self):
        if self.start_time is not None and self.end_time is not None :
            return('CUSTOM')
        else :
            return self._time_range.upper()

    @property
    def start_time(self):
        return format_esm_time(self._start_time)

    @property
    def end_time(self):
        return format_esm_time(self._end_time)

    @time_range.setter
    def time_range(self, time_range):
        """
        Set the time range of the query to the specified string value. 
        Defaulf QueryManager.DEFAULT_TIME_RANGE
        """

        if not time_range :
            self.time_range=self.DEFAULT_TIME_RANGE

        elif isinstance(time_range, str):
            time_range=time_range.upper()
            if time_range in self.POSSIBLE_TIME_RANGE :
                if time_range != 'CUSTOM':
                    self.start_time=None
                    self.end_time=None
                self._time_range=time_range
            else:
                raise ValueError("The time range must be in "+str(self.POSSIBLE_TIME_RANGE))
        else:
            raise ValueError('time_range must be a string or None')

    
    @start_time.setter
    def start_time(self, start_time):
        """
        Set the time start of the query.
        If none : equivalent current_day start 00:00:00
        """
        
        if not start_time:
            self.start_time = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        elif isinstance(start_time, str):
            self.start_time = convert_to_time_obj(start_time)
        elif isinstance(start_time, datetime.datetime):
            self._start_time = start_time
        else:
            raise ValueError("Time must be string or datetime object.")
                
    
    @end_time.setter
    def end_time(self, end_time):
        """
        Set the time end of the query.
        If none : equivalent now
        """
       
        if not end_time:
            self.end_time = datetime.datetime.now()
        elif isinstance(end_time, str):
            self.end_time = convert_to_time_obj(end_time)
        elif isinstance(end_time, datetime.datetime):
            self._end_time = end_time
        else:
            raise ValueError("Time must be string or datetime object.")

    @abc.abstractproperty
    def filters(self):
        raise NotImplementedError()

    @filters.setter
    def filters(self, filters):
        
        if isinstance(filters, list):
            for f in filters :
                self.add_filter(f)

        elif isinstance(filters, tuple):
            self.add_filter(filters)

        elif filters is None :
            self.clear_filters()
        
        else :
            raise NitroError("Illegal type for the filter object, it must be a list, a tuple or None.")

    
    @abc.abstractmethod
    def add_filter(self, filter):
        pass

    @abc.abstractmethod
    def clear_filters(self):
        pass 

    @abc.abstractmethod
    def _load_data(self):
        """
        Must return a tuple (items, completed)
        completed = True if all the data that should be load is loaded
        """
        pass

    @staticmethod
    def action_load_data(querymanager):
        return(querymanager.load_data())

    @abc.abstractmethod
    def load_data(self):
        """
        Method to load the data from the SIEM
        Split the query in defferents time slots if the query apprears not to be completed.
        Splitting is done by duplicating current object, setting different times,
        and re-loading results. First your query time is split in slots of size `delta` 
        in [performance] section of the config and launch asynchronously in queue of length `max_workers`.
        Secondly, if the sub queries are not completed, divide them in the number of `slots`, this step is
        executed recursively a maximum of `max_query_depth`.
        Returns a QueryManager.
        """

        items, completed = self._load_data()

        if not completed :
            #If not completed the query is split and items aren't actually used

            if self.query_depth <= self.nitro.config.max_query_depth :
                #log.info("The query data couldn't be loaded in one request, separating it in sub-queries...")

                if self.time_range != 'CUSTOM': #can raise a NotImplementedError if unsupported time_range
                    start, last = timerange_gettimes(self.time_range)
                else :
                    start, last = self.start_time, self.end_time

                if self.split_strategy == 'delta'  :
                    division = {'delta':self.nitro.config.delta} 
                elif self.split_strategy == 'slots':
                    division = {'slots':self.nitro.config.slots}

                times=divide_times(start, last, **division)
                sub_queries=list()

                for time in times :
                    sub_query = copy.copy(self)

                    sub_query.compute_time_range=False
                    sub_query.time_range='CUSTOM'
                    sub_query.start_time=time[0].isoformat()
                    sub_query.end_time=time[1].isoformat()
                    sub_query.load_async=False
                    sub_query.query_depth=self.query_depth+1
                    sub_query.split_strategy='slots'
                    sub_queries.append(sub_query)

                if self.load_async :
                    log.info('Loading data from '+self.start_time+' to '+self.end_time+'. Spliting query in '+str(division)+' ...')

                results = Manager.perform_static(QueryManager.action_load_data, sub_queries, 
                    asynch=self.load_async, progress=(self.query_depth==1))

                #Flatten the list of lists in a list
                items=[item for sublist in results for item in sublist]
                
            else :
                log.warning("The query couldn't be fully executed, reached maximum query_depth :"+str(self.query_depth))

        self.data=items
        return(Manager(alist=items))

class TestQueryManager(QueryManager):
    pass

class QueryFilter(NitroObject):

    _possible_filters = []

    def __init__(self):
        super().__init__()

        #Setting up static constant
        """ Not checking dynamically the validity of the fields cause makes too much of unecessary requests
            self._possible_filters = self._get_possible_filters()
            """

    def _get_possible_filters(self):
        return(self.nitro.request('get_possible_filters'))

    @abc.abstractproperty
    def config_dict(self):
        pass

    def refresh(self):
        log.warning("Can't refresh filter "+str(self))

    @property
    def json(self):
        return (json.dumps(self, indent=4, cls=NitroObject.NitroJSONEncoder))
    @property
    def text(self):
        return str(self.config_dict)