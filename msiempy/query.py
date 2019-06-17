import datetime
import abc
import copy
import json
import logging
log = logging.getLogger('msiempy')

from .base import Manager, NitroError, NitroObject
from .utils import format_esm_time, convert_to_time_obj, timerange_gettimes, parse_timedelta, divide_times

class QueryManager(Manager):
    """
    Base class for query based managers : AlarmManager, EventManager
    QueryManager object can handle time_ranges and time splitting.
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
    List of possible time ranges
    """

    def __init__(self, time_range=None, start_time=None, end_time=None, filters=None, 
        query_rec=None, load_async=True, split_strategy='delta', *arg, **kwargs):
        """
        Abstract base class that handles the time ranges operations, loading data from the SIEM.

        Params
        ======
            time_range : Query time range. String representation of a time range. 
                See `msiempy.base.QueryManager.POSSIBLE_TIME_RANGE`
            start_time : Query starting time, can be a string or a datetime object. Parsed with dateutil.
            end_time : Query endding time, can be a string or a datetime object. Parsed with dateutil.
            filters : List of filters applied to the query
            query_depth : Maximum number of splitting recursions. Defaulted to zéro,
                meaning no sub-queries will be generated. 
            load_async : Load asynchonously the sub-queries. Defaulted to True.
            split_strategy : Sub-queries can be genrated by splitting the time range in a fixed number of slots (`slots`)
                or by dividing the time range in equals duration slots (`delta`).
        """

        super().__init__(*arg, **kwargs)

        self.nitro.config.default_rows #nb rows per request : eq limit/page_size
        self.nitro.config.max_rows #max nb rows 

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
        else :
            self.time_range=time_range

        self.load_async=load_async
        self.query_rec=query_rec if query_rec is not None else self.nitro.config.max_query_depth
        self.split_strategy=split_strategy


    @property
    def time_range(self):
        """
        Returns the query time range. See `msiempy.query.QueryManager.POSSIBLE_TIME_RANGE`.
        Return 'CUSTOM' if internal _time_range is None and start_time annd end_time are set.
        """
        if self.start_time is not None and self.end_time is not None :
            return('CUSTOM')
        else :
            return self._time_range.upper()

    @property
    def start_time(self):
        """
        Return the start time of the query in the right SIEM format.
            See `msiempy.utils.format_esm_time()`
        Use _start_time to get the datetime object
        """
        return format_esm_time(self._start_time)

    @property
    def end_time(self):
        """
        Return the end time of the query in the right SIEM format.
            See `msiempy.utils.format_esm_time()`
        Use _end_time to get the datetime object
        """
        return format_esm_time(self._end_time)

    @time_range.setter
    def time_range(self, time_range):
        """
        Set the time range of the query to the specified string value. 
        Defaulf `msiempy.queryQueryManager.DEFAULT_TIME_RANGE`.
        Note : the time range is upper cased automatically.
        Throw VallueError if unrecognized time range.
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
        start_time can be a string or a datetime.
        If None, equivalent current_day start 00:00:00.
        
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
        end_time can be a string or a datetime.
        If None, equivalent now.
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
        """ 
        Filter propertie getter. Returns a list of filters.
        #TODO find a better solution to integrate the filter propertie
        """
        raise NotImplementedError()

    @filters.setter
    def filters(self, filters):
        """
        Query filters property : can be a list of tuple(field, [values]) 
            or just a tuple. None value will call `msiempy.query.QueryManager.clear_filters()`
        Throws AttributeError if type not supported.
        """
        
        if isinstance(filters, list):
            for f in filters :
                self.add_filter(f)

        elif isinstance(filters, tuple):
            self.add_filter(filters)

        elif filters is None :
            self.clear_filters()
        
        else :
            raise AttributeError("Illegal type for the filter object, it must be a list, a tuple or None.")

    
    @abc.abstractmethod
    def add_filter(self, filter):
        """
        Method that figures out the way to add a filter to the query.
        """
        pass

    @abc.abstractmethod
    def clear_filters(self):
        """
        Method that fiures out the way to remove all filters to the query.
        """
        pass 

    @abc.abstractmethod
    def _load_data(self):
        """
        Rturn a tuple (items, completed).
        completed = True if all the data that should be load is loaded.
        """
        pass

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

        #
        """

        items, completed = self._load_data()

        if not completed :
            #If not completed the query is split and items aren't actually used

            if self.query_rec > 0 :
                #log.info("The query data couldn't be loaded in one request, separating it in sub-queries...")

                if self.time_range != 'CUSTOM': #can raise a NotImplementedError if unsupported time_range
                    start, end = timerange_gettimes(self.time_range)
                else :
                    start, end = self.start_time, self.end_time

                times=divide_times(start, end, slots=self.nitro.config.slots)
                sub_queries=list()

                for time in times :
                    sub_query = copy.copy(self)

                    sub_query.compute_time_range=False
                    sub_query.time_range='CUSTOM'
                    sub_query.start_time=time[0].isoformat()
                    sub_query.end_time=time[1].isoformat()
                    sub_query.load_async=False
                    sub_query.query_rec=self.query_rec-1
                    sub_query.split_strategy='slots'
                    sub_queries.append(sub_query)

                results = self.perform(QueryManager.load_data, sub_queries, 
                    asynch=self.load_async, progress=True, message='Loading data from '+self.start_time+' to '+self.end_time+'. Spliting query in {} slots'.format(self.nitro.config.slots))

                #Flatten the list of lists in a list
                items=[item for sublist in results for item in sublist]
                
            else :
                log.warning("The query couldn't be fully executed")

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

    def get_possible_filters(self):
        """
        Return all the fields that you can filter on in a query.
        """
        return(self.nitro.request('get_possible_filters'))

    @abc.abstractproperty
    def config_dict(self):
        """
        Dump a filter in the right format.
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
        Dump the filter as a json
        """
        return (json.dumps(self, indent=4, cls=NitroObject.NitroJSONEncoder))
    
    @property
    def text(self):
        """
        Text representation
        """
        return str(self.config_dict)

class GroupFilter(QueryFilter):
    """
        Based on EsmFilterGroup. See SIEM api doc.
        Used to dump groups of filters in the right format.
    """

    def __init__(self, *filters, logic='AND') :
        """
        filter : a list of filters, it can be FieldFilter or GroupFilter aka -  base.QueryFilter
        logic : 'AND' or 'OR' (i think)
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

    """List of possible type of value and the associated keyword to pass
        to
        """
    POSSIBLE_VALUE_TYPES=[
            {'type':'EsmWatchlistValue',    'key':'watchlist'},
            {'type':'EsmVariableValue',     'key':'variable'},
            {'type':'EsmBasicValue',        'key':'value'},
            {'type':'EsmCompoundValue',     'key':'values'}]


    def __init__(self, name, values, operator='IN') :
        """
        name : field name as string
        values : list of values the field is going 
                 to be tested againts with the specified orperator
        orperator : string representing 
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
        Field name property getter.
        """
        return (self._name)
    
    @property
    def operator(self):
        """
        Field operator property getter.
        """
        return (self._operator)

    @property
    def values(self):
        """
        Field values property getter.
        """
        return (self._values)

    @name.setter
    def name(self, name):
        """
        Could checking dynamically the validity of the fields but turned off cause it was loading to much 
        #TODO add the list of fields check in better way and STORE the list one time only. Use class property ?
        """
        if True : # Not checking dynamically the validity of the fields cause makes too much of unecessary requests any(f.get('name', None) == name for f in self._possible_filters):
            self._name = name
        else:
            raise AttributeError("Illegal value for the "+name+" field. The filter must be in :"+str([f['name'] for f in self._possible_filters]))
       

    @operator.setter
    def operator(self, operator):
        """
        Check the value against the list of possible operators and trow error if not present.
        """
        try:
            if operator in self.POSSIBLE_OPERATORS :
                self._operator = operator
            else:
                raise AttributeError("Illegal value for the filter operator "+operator+". The operator must be in "+str(self.POSSIBLE_OPERATORS))
        except:
            raise
        
    def add_value(self, type, **args):
        """
        Add a new value to the field filter.
        
        Args could be :
            (type='EsmBasicValue',      value='a value'}. or
            (type='EsmWatchlistValue',  watchlist=1)   or 
            (type='EsmVariableValue',   variable=1}  or
            (type='EsmCompoundValue',   values=['.*']}
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
        Wrapper arround add_value to add a EsmBasicValue
        """
        self.add_value(type='EsmBasicValue', value=value)

    @values.setter
    def values(self, values):
        """
        Set a list of values calls add_value if value is a 
            dict or calls add_basic_value if int, float or str
        
        """
        for val in values :
            if isinstance(val, dict):
                self.add_value(**val)

            elif isinstance(val, (int, float, str)) :
                self.add_basic_value(val)