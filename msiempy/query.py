"""Provide time ranged filtered query wrapper.
"""

import datetime
import abc
import copy
import json
import logging
log = logging.getLogger('msiempy')

from . import NitroList, NitroError, NitroObject
from .utils import format_esm_time, convert_to_time_obj, timerange_gettimes, parse_timedelta, divide_times

class FilteredQueryList(NitroList):
    """
    Base class for query based managers : AlarmManager, EventManager
    FilteredQueryList object can handle time_ranges and time splitting.
    """
    
    DEFAULT_TIME_RANGE="CURRENT_DAY"
    """
    If you don't specify any `time_range`, act like if it was "CURRENT_DAY".
    """

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
    """
    List of possible time ranges : `"CUSTOM",
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
            "PREVIOUS_YEAR"`
    """

    def __init__(self, time_range=None, start_time=None, end_time=None, filters=None, 
        load_async=True, requests_size=500, max_query_depth=0,
            __parent__=None, *arg, **kwargs):
        """
        Abstract base class that handles the time ranges operations, loading data from the SIEM.

        Parameters:  
    
        - `time_range` : Query time range. String representation of a time range. 
            See `msiempy.query.FilteredQueryList.POSSIBLE_TIME_RANGE`
        - `start_time` : Query starting time, can be a string or a datetime object. Parsed with dateutil.
        - `end_time` : Query endding time, can be a string or a datetime object. Parsed with dateutil.
        - `filters` : List of filters applied to the query.
        - `load_async` : Load asynchonously the sub-queries. Defaulted to True.
        - `requests_size` : number of items per request.
        - `max_query_depth` : maximum number of supplement reccursions of division of the query times
            Meaning, if requests_size=500, slots=5 and max_query_depth=3, then the maximum capacity of 
            the list is (500*5)*(500*5)*(500*5) = 15625000000
            
        """

        super().__init__(*arg, **kwargs)

        #Store the query parent 
        self.__parent__=__parent__
        self.not_completed=False

        #self.nitro.config.default_rows #nb rows per request : eq limit/page_size = requests_size
        #self.nitro.config.max_rows #max nb rows 

        #Declaring attributes and types
        self._time_range=str()
        self._start_time=None
        self._end_time=None

        #self.filters=filters filter property setter should be called in the concrete class
        #TODO find a better solution to integrate the filter propertie

        self.load_async=load_async

        if start_time is not None and end_time is not None :
            self.start_time=start_time
            self.end_time=end_time
            self.time_range='CUSTOM'
        else :
            self.time_range=time_range

        self.load_async=load_async
        self.requests_size=requests_size
        self.__init_max_query_depth__=max_query_depth
        self.query_depth_ttl=max_query_depth


    @property
    def __root_parent__(self):
        """
        Internal method that return the first query of the query tree
        """
        if self.__parent__==None:
            return self
        else :
            return self.__parent__.__root_parent__

    @property
    def time_range(self):
        """
        Query time range. See `msiempy.query.FilteredQueryList.POSSIBLE_TIME_RANGE`.
        Default to `msiempy.query.FilteredQueryList.DEFAULT_TIME_RANGE` (CURRENT_DAY).
        Note that the time range is upper cased automatically.
        Raises `VallueError` if unrecognized time range is set and `AttributeError` if not the right type.
        """
        return self._time_range.upper()

    @time_range.setter
    def time_range(self, time_range):
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
            raise AttributeError('time_range must be a string or None')

    @property
    def start_time(self):
        """
        Start time of the query in the right SIEM format. See `msiempy.utils.format_esm_time()`
        Use `_start_time` to get the datetime object. You can set the `star_time` as a `str` or a `datetime`.
        If `None`, equivalent CURRENT_DAY start 00:00:00. Raises `ValueError` if not the right type.
        """
        return format_esm_time(self._start_time)

    @start_time.setter
    def start_time(self, start_time):
        if isinstance(start_time, str):
            self.start_time = convert_to_time_obj(start_time)
        elif isinstance(start_time, datetime.datetime):
            self._start_time = start_time
        elif start_time==None:
             self._start_time=None#raise ValueError("Time must be string or datetime object, not None")#self.start_time = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            raise ValueError("Time must be string or datetime object.")

    @property
    def end_time(self):
        """
        End time of the query in the right SIEM format.  See `msiempy.utils.format_esm_time()`
        Use _end_time to get the datetime object. You can set the `end_time` as a `str` or a `datetime`.
        If `None`, equivalent CURRENT_DAY ends now. Raises `ValueError` if not the right type.
        """
        return format_esm_time(self._end_time)

    @end_time.setter
    def end_time(self, end_time):       
        if isinstance(end_time, str):
            self.end_time = convert_to_time_obj(end_time)
        elif isinstance(end_time, datetime.datetime):
            self._end_time = end_time
        elif end_time==None:
             self._end_time=None#raise ValueError("Time must be string or datetime object, not None")
        else:
            raise ValueError("Time must be string or datetime object.")

    @abc.abstractproperty
    def filters(self):
        """ 
        Filter property : Returns a list of filters.
        Can be set with list of tuple(field, [values]) or `msiempy.query.QueryFilter` in the case of a `msiempy.event.EventManager` query. A single tuple is also accepted. 
        None value will call `msiempy.query.FilteredQueryList.clear_filters()`
        Raises `AttributeError` if type not supported.
        TODO find a better solution to integrate the filter propertie
        """
        raise NotImplementedError()

    @filters.setter
    def filters(self, filters):
        if isinstance(filters, list):
            for f in filters :
                self.add_filter(f)

        elif isinstance(filters, tuple):
            self.add_filter(filters)

        elif filters == None :
            self.clear_filters()
        
        else :
            raise AttributeError("Illegal type for the filter object, it must be a list, a tuple or None.")

    
    @abc.abstractmethod
    def add_filter(self, filter):
        """Method that figures out the way to add a filter to the query.
        """
        pass

    @abc.abstractmethod
    def clear_filters(self):
        """Method that fiures out the way to remove all filters to the query.
        """
        pass 

    @abc.abstractmethod
    def _load_data(self, workers):
        """
        Rturn a tuple (items, completed).
        completed = True if all the data that should be load is loaded.
        """
        pass

    @abc.abstractmethod
    def load_data(self, workers=15, slots=4, delta='24h'):
        """
        Method to load the data from the SIEM.
        Split the query in defferents time slots if the query apprears not to be completed.
        Splitting is done by duplicating current object, setting different times,
        and re-loading results. First your query time is split in slots of size `delta` 
        if the sub queries are not completed, divide them in the number of `slots`, this step is
        If you're looking for `max_query_depth`, it's define at the creation of the query list.

        Returns a FilteredQueryList.
        
        Note :
            IF you looking for load_async = True/False, you should pass this to the constructor method `msiempy.query.FilteredQueryList`
                or by setting the attribute manually like `manager.load_asynch=True`
            Only the first query is loaded asynchronously.

        Parameters:  
    
        - `workers` : numbre of parrallels task
        - `slots` : number of time slots the query can be divided. The loading bar is 
            divided according to the number of slots
        - `delta` : exemple : '24h', the query will be firstly divided in chuncks according to the time delta read
            with dateutil.
        
        """

        items, completed = self._load_data(workers=workers)

        if not completed :
            #If not completed the query is split and items aren't actually used

            if self.query_depth_ttl > 0 :
                #log.info("The query data couldn't be loaded in one request, separating it in sub-queries...")

                if self.time_range != 'CUSTOM': #can raise a NotImplementedError if unsupported time_range
                    start, end = timerange_gettimes(self.time_range)
                else :
                    start, end = self.start_time, self.end_time

                if self.__parent__ == None and isinstance(delta, str) :
                    #if it's the first query and delta is speficied, cut the time_range in slots according to the delta
                    times=divide_times(start, end, delta=parse_timedelta(delta))
                    
                else :times=divide_times(start, end, slots=slots)
                        #IGONORING THE CONFIG ### : self.nitro.config.slots)
                
                sub_queries=list()

                for time in times :
                    """
                    """
                    sub_query = copy.copy(self)
                    sub_query.__parent__=self
                    sub_query.compute_time_range=False
                    sub_query.time_range='CUSTOM'
                    sub_query.start_time=time[0].isoformat()
                    sub_query.end_time=time[1].isoformat()
                    sub_query.load_async=False
                    sub_query.query_depth_ttl=self.query_depth_ttl-1
                    #sub_query.requests_size=requests_size
                    sub_queries.append(sub_query)

            
                results = self.perform(FilteredQueryList.load_data, sub_queries, 
                    #The sub query is asynch only when it's set to True and it's the first query
                    asynch=False if not self.load_async else (self.__parent__==None),
                    progress=self.__parent__==None, 
                    message='Loading data from '+self.start_time+' to '+self.end_time+'. In {} slots'.format(len(times)),
                    func_args=dict(slots=slots),
                    workers=workers)

                #Flatten the list of lists in a list
                items=[item for sublist in results for item in sublist]
                
            else :
                if not self.__root_parent__.not_completed :
                    log.warning("The query won't fully complete. Try to divide in more slots or increase the requests_size")
                    self.__root_parent__.not_completed=True

        self.data=items
        return(NitroList(alist=items)) #return self ?

class QueryFilter(NitroObject):
    """Base class for all SIEM query objects, declares the `config_dict` abstract property in order to dump the filter as JSON.
    """
    _possible_filters = []

    def __init__(self):
        super().__init__()

        #Setting up static constant
        """Not checking dynamically the validity of the fields cause makes too much of unecessary requests
            self._possible_filters = self._get_possible_filters()
            """

    def get_possible_filters(self):
        """
        Return all the fields that you can filter on in a query.
        """
        return(self.nitro.request('get_possible_filters'))

    @abc.abstractproperty
    def config_dict(self):
        """
        Dump a filter in the right JSON format.
        """
        pass

    def refresh(self):
        """
        Superclass method.
        """
        log.warning("Can't refresh filter "+str(self))

    @property
    def json(self):
        """
        Dump the filter as a json.
        """
        return (json.dumps(self, indent=4, cls=NitroObject.NitroJSONEncoder))
    
    @property
    def text(self):
        """
        Text representation of `config_dict` property.
        """
        return str(self.config_dict)

class GroupFilter(QueryFilter):
    """
        Based on EsmFilterGroup. See SIEM api doc.
        Used to dump groups of filters in the right format.
    """

    def __init__(self, filters, logic='AND') :
        """Parameters :  
        - `filters` : a list of filters, it can be `msiempy.query.FieldFilter` or `msiempy.query.GroupFilter`
        - `logic` : 'AND' or 'OR'
        """
        super().__init__()
        
        #Declaring attributes
        self.filters=filters
        self.logic=logic

    @property
    def config_dict(self):
        """
        Could call recursively if there is other GroupFilter(s) object nested.
        Dump a filter in the right format.
        """
        return({
            "type": "EsmFilterGroup",
            "filters": [f.config_dict for f in self.filters],
            "logic":self.logic
            })
        
class FieldFilter(QueryFilter):
    """
    Based on EsmFieldFilter. See SIEM api doc.
    Used to dump a filter in the right format.
    """

    """List of possibles operators        
        """
    POSSIBLE_OPERATORS=['IN',
        'NOT_IN',
        'GREATER_THAN',
        'LESS_THAN',
        'GREATER_OR_EQUALS_THAN',
        'LESS_OR_EQUALS_THAN',
        'NUMERIC_EQUALS',
        'NUMERIC_NOT_EQUALS',
        'DOES_NOT_EQUAL',
        'EQUALS',
        'CONTAINS',
        'DOES_NOT_CONTAIN',
        'REGEX']

    """List of possible operators : `'IN',
        'NOT_IN',
        'GREATER_THAN',
        'LESS_THAN',
        'GREATER_OR_EQUALS_THAN',
        'LESS_OR_EQUALS_THAN',
        'NUMERIC_EQUALS',
        'NUMERIC_NOT_EQUALS',
        'DOES_NOT_EQUAL',
        'EQUALS',
        'CONTAINS',
        'DOES_NOT_CONTAIN',
        'REGEX'`
        """

    POSSIBLE_VALUE_TYPES=[
            {'type':'EsmWatchlistValue',    'key':'watchlist'},
            {'type':'EsmVariableValue',     'key':'variable'},
            {'type':'EsmBasicValue',        'key':'value'},
            {'type':'EsmCompoundValue',     'key':'values'}]
    """
    List of possible value type. See `msiempy.query.FieldFilter.add_value`.
    """


    def __init__(self, name, values, operator='IN') :
        """
        Parameters:

        - `name` : field name as string.
        - `values` : list of values the field is going to be tested againts with the specified orperator.
        - `orperator` : operator, see `msiempy.query.FieldFilter.POSSIBLE_OPERATORS`.
        """
        super().__init__()
        #Declaring attributes
        self._name=str()
        self._operator=str()
        self._values=list()
        self.name = name
        self.operator = operator
        self.values = values

    @property
    def config_dict(self):
        """
        Dump a filter in the right format.
        """
        return ({
            "type": "EsmFieldFilter",
            "field": {"name": self.name},
            "operator": self.operator,
            "values": self.values
            })

    @property
    def name(self):
        """
        Field name property. Example : `SrcIP`. See full list here: https://github.com/mfesiem/msiempy/blob/master/static/all_filters.json
        """
        return (self._name)

    @name.setter
    def name(self, name):
        if True : # Not checking dynamically the validity of the fields cause makes too much of unecessary requests any(f.get('name', None) == name for f in self._possible_filters):
            self._name = name
        else:
            raise AttributeError("Illegal value for the "+name+" field. The filter must be in :"+str([f['name'] for f in self._possible_filters]))
    
    @property
    def operator(self):
        """
        Field operator property. Check the value against the list of possible operators and trow `AttributeError` if not present.
        """
        return (self._operator)
    
    @operator.setter
    def operator(self, operator):
        try:
            if operator in self.POSSIBLE_OPERATORS :
                self._operator = operator
            else:
                raise AttributeError("Illegal value for the filter operator "+operator+". The operator must be in "+str(self.POSSIBLE_OPERATORS))
        except:
            raise

    @property
    def values(self):
        """
        Values property.
        Set a list of values by calling `msiempy.query.FilteredQueryList.add_value()` if value is a 
        `dict` or calls `msiempy.query.FilteredQueryList.add_basic_value()` if value type is `int`, `float` or `str`.
        Values will always be added to the filter. To remove values, handle directly the `_values` property.

        Example:  
        ```
            >>> filter = FieldFilter(name='DstIP',values=['10.1.13.0/24'],operator='IN')
            >>> filter.values=['10.1.14.0/8', {'type':'EsmWatchlistValue', 'watchlist':42}]
            >>> filter.config_dict
            {'type': 'EsmFieldFilter', 
            'field': {'name': 'DstIP'}, 
            'operator': 'IN', 
            'values': [{'type': 'EsmBasicValue', 'value': '10.1.13.0/24'},
                {'type': 'EsmBasicValue', 'value': '10.1.14.0/8'},
                {'type': 'EsmWatchlistValue', 'watchlist': 42}]}
                ```
            
        """
        return (self._values)

    @values.setter  
    def values(self, values):
        for val in values :
            if isinstance(val, dict):
                self.add_value(**val)

            elif isinstance(val, (int, float, str)) :
                self.add_basic_value(val)
        
    def add_value(self, type, **args):
        """
        Add a new value to the field filter.
        
        Parameters (`**args`) could be (depending of the value type):  
        - `{ type='EsmBasicValue', value='a value'}`  
        - `{ type='EsmWatchlistValue', watchlist=1}`  
        - `{ type='EsmVariableValue', variable=1}`  
        - `{ type='EsmCompoundValue', values=['.*']}`  

        Raises `KeyError` or `AttributeError` if you don't respect the correct type/key/value combo.
        Note : Filtering query with other type of filter than 'EsmBasicValue' is not tested.
        """
        try:
            type_template=None
            
            #Look for the type of the object ex EsmBasicValue
            # it' used to know the type and name of value parameter we should receive next
            for possible_value_type in self.POSSIBLE_VALUE_TYPES :
                if possible_value_type['type'] == type :
                    type_template=possible_value_type
                    if type != 'EsmBasicValue' :
                        log.warning("Filtering query with other type of filter than 'EsmBasicValue' is not tested.")                            
                    break

            #Error throwing
            if type_template is not None :
                if type_template['key'] in args :
                    
                    # Adds a new value to a fields filter
                    # Filtering query with other type of filter than 'EsmBasicValue' is not tested.
                    value = args[type_template['key']]
                    if type == 'EsmBasicValue' :
                        value=str(value)
                        #log.debug('Adding a basic value to filter ('+self.text+') : '+value)
                    self._values.append({'type':type, type_template['key']:value})
                    #log.debug('The value was appended to the list: '+str(self))
                    
                #Error throwing
                else: raise KeyError ('The valid key value parameter is not present')
            else: raise KeyError ('Impossible filter')
        except KeyError as err:
            raise AttributeError("You must provide a valid named parameters containing the type and values for this filter. The type/keys must be in "+str(self.POSSIBLE_VALUE_TYPES)+"Can't be type="+str(type)+' '+str(args)+". Additionnal indicator :"+str(err) )

    def add_basic_value(self, value):
        """
        Wrapper arround add_value to add a EsmBasicValue.
        """
        self.add_value(type='EsmBasicValue', value=value)

    