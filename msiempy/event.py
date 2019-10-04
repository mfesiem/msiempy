"""Provide event management.
"""

import time
import json
import abc
import collections
import logging
import copy
from datetime import datetime
log = logging.getLogger('msiempy')

from . import NitroObject, NitroDict, NitroError, FilteredQueryList
from .__utils__ import timerange_gettimes, parse_query_result, format_fields_for_query, divide_times, parse_timedelta

class InDepthQueryList(FilteredQueryList):
    pass

class EventManager(FilteredQueryList):
    """Interface to query and manage events.
    Inherits from `msiempy.FilteredQueryList`.
    """ 

    #Constants
    #TODO Try grouped queries !
    TYPE='EVENT'
    GROUPTYPE='NO_GROUP'
    POSSBILE_ROW_ORDER=[
            'ASCENDING',
            'DESCENDING'
    ]

    # Declaring static value containing all the possibles
    # event fields, should be loaded once (when the session start ?)
    _possible_fields = []

    def __init__(self, fields=None, 
        order=None, limit=500, filters=None, 
        compute_time_range=True, #to remove ~> use it just when max_query_depth>0
        max_query_depth=0, #to move to load_data()
        __parent__=None,
        *args, **kwargs):
        """
        Paramters:  
           
        - `fields` : list of strings representing all fields you want to apprear in the Events records.
            Get the list of possible fields by calling `msiempy.event.EventManager.get_possible_fields()` method or see 
            `msiempy.event.Event`.
            Some defaults fields will always be present unless removed with `remove()` method, see notes.
        - `order` : **Not implemented yet** . 
            tuple (direction, field) or a list of filters in the SIEM format.
            will set the first order according to (direction, fields).
                -> same as using the property setter.
            If you pass a list here, will use the this raw list as the SIEM `order` field.
            Structure must be in correct format
                -> same as setting _order property directly.
        - `limit` : max number of rows per query, by default takes the value in config `default_rows` option.
        - `filters` : list of filters. A filter can be a `tuple(field, [values])` or it can be a `msiempy.event.QueryFilter`
        if you wish to use advanced filtering.
        - `compute_time_range` : False if you want to send the actualy time_range in parameter for the initial query.
            Defaulted to True cause the query splitting implies computing the time_range anyway.
        - `max_query_depth` : maximum number of supplement reccursions of division of the query times
            Meaning, if requests_size=500, slots=5 and max_query_depth=3, then the maximum capacity of 
            the list is (500*5)*(500*5)*(500*5) = 15625000000
        - `*args, **kwargs` : Parameters passed to `msiempy.FilteredQueryList`
           
            
        Notes :
            
        - `__init__()` parameters are also properties.
        ```
            >>>em=EventManager(fields=['SrcIP','DstIP'],
                    order=('DESCENDING''LastTime'),
                    filters=[('DstIP','4.4.0.0/16','8.8.0.0/16')])
            >>>em.load_data()
        ```

        is equivalent to :
        ```
            >>>em=EventManager()
            >>>em.fields=['SrcIP','DstIP'],
            >>>em._order=[{  "direction": 'DESCENDING',
                            "field": { "name": 'LastTime' }  }]
            >>>em.filters=[('DstIP','4.4.0.0/16','8.8.0.0/16')]
            >>>em.load_data()
        ```
        - You can remove fields from default `msiempy.event.Event` fields.
        ```
            >>>em=EventManager()
            >>>em.fields.remove('SrcIP')
        ```
                
        """

        #Store the query parent 
        self.__parent__=__parent__

        #Store the query ttl
        self.__init_max_query_depth__=max_query_depth
        self.query_depth_ttl=max_query_depth

        #Declaring attributes
        self._filters=list()
        self._order=dict()

        #Setting the default fields
        self.fields=Event.DEFAULTS_EVENT_FIELDS
        
        #Adds the specified fields and make sure there is no duplicates
        if fields :
            self.fields=list(set(self.fields+fields))

        #Set the compute_time_range propertir that is going to be used when time_range setter is called
        self.compute_time_range=compute_time_range

        #Calling super constructor : time_range set etc...
        super().__init__(*args, **kwargs)

        #Setting limit according to config or limit argument
        #TODO Try to load queries with a limit of 10k and get result as chucks of 500 with starPost nbRows
        #   and compare efficiency
        self.limit=int(limit)
        #we can ignore Access to member 'requests_size' before its definition line 95pylint(access-member-before-definition)
        #It's define in FilteredQueryList __init__()

        self.requests_size=self.limit

        if isinstance(order, list): #if a list is passed for the prder, will replace the whole param supposed in correct SIEM format
            self._order=order
        else:
            self._order=[{
                "direction": 'DESCENDING',
                "field": {
                    "name": 'LastTime'
                    }
                }]
            self.order=order #if a tuple is passed , will set the first order according to (direction, fields)

        #TODO : find a solution not to use this
        #callign super().filters=filters #https://bugs.python.org/issue14965
        super(self.__class__, self.__class__).filters.__set__(self, filters)

        #Type cast all items in the list "data" to events type objects
        #Casting all data to Event objects, better way to do it ?
        collections.UserList.__init__(self, [Event(adict=item) for item in self.data if isinstance(item, (dict, NitroDict))])

    @property
    def order(self):
        """
        Orders representing the what the SIEM is expecting as the 'order'.
        The `order` must be tuple (direction, field). Only the first order can be set by this property.
        Use _order to set with SIEM format.
        Note that `order` property handling is **not implemented yet**.
        """
        return(self._order)

    @order.setter
    def order(self, order):
        if order is None :
            self._order=[{
                "direction": 'DESCENDING',
                "field": {
                    "name": 'LastTime'
                    }
                }]
        elif isinstance(order, tuple) :
            if order[0] in self.POSSBILE_ROW_ORDER:
                self._order[0]['direction']=order[0]
                self._order[0]['field']['name']=order[1]
            else:
                raise AttributeError("Illegal order value : "+str(order[0])+". The order must be in :"+str(self.POSSBILE_ROW_ORDER))
        else :
            raise AttributeError("Illegal type for argument order. Can onyl be a tuple is using the property setter. You can diretly specify a list of orders (SIEM format) by setting _order property.")

    @property
    def filters(self):
        """
        JSON SIEM formatted filters for the query by calling reccursively : `msiempy.event.QueryFilter.config_dict`.
        See `msiempy.FilteredQueryList.filters`.
        """
        return([f.config_dict for f in self._filters])

    def add_filter(self, afilter):
        """
        Concrete description of the `msiempy.FilteredQueryList` method.
        It can take a `tuple(fiels, [values])` or a `msiempy.event.QueryFilter` subclass.
        """
        if isinstance(afilter, tuple) :
            self._filters.append(FieldFilter(afilter[0], afilter[1]))

        elif isinstance(afilter, QueryFilter) :
            self._filters.append(afilter)
        
        else :
            raise NitroError("Sorry the filters must be either a tuple(fiels, [values]) or a QueryFilter sub class.")

    def clear_filters(self):
        """
        Replace all filters by a non filtering rule.
        Acts like the is not filters.
        """ 
        self._filters=[FieldFilter('SrcIP', ['0.0.0.0/0',])]
    
    @property
    def time_range(self):
        """Re-implemented the `msiempy.FilteredQueryList.time_range` to have better control on the property setter.
        If `compute_time_range` is True (by default it is), try to get a start and a end time with `msiempy.utils.timerange_gettimes()`
        """
        return(super().time_range)

    @time_range.setter
    def time_range(self, time_range):
        if time_range!=None and time_range!='CUSTOM' and self.compute_time_range :
            try :
                times = timerange_gettimes(time_range)
                self._time_range='CUSTOM'
                self._start_time=times[0]
                self._end_time=times[1]
            # timerange_gettimes raises AttributeError until
            # all timeranges are supported
            except AttributeError as err:
                log.warning(err)
                #TODO : find a soltuion not to use this
                #Calling super().time_range=time_range
                #https://bugs.python.org/issue14965
                super(self.__class__, self.__class__).time_range.__set__(self, time_range)
            except :
                raise
        else :
            #TODO : find a soltuion not to use this
            super(self.__class__, self.__class__).time_range.__set__(self, time_range)

    def get_possible_fields(self):
        """
        Indicate a list of possible fields that you can request in a query.
        The list is loaded from the SIEM.
        """
        return self.nitro.request('get_possible_fields', type=self.TYPE, groupType=self.GROUPTYPE)

    def qry_load_data(self):
        """"
        Concrete helper method to execute the query and load the data : 
            -> Submit the query 
            -> Wait the query to be executed
            -> Get and parse the events

        Returns : `tuple` : ( `msiempy.event.EventManager`, Status of the query : `completed` )

        """
        query_infos=dict()

        #Queries api calls are very different if the time range is custom.
        if self.time_range == 'CUSTOM' :
            query_infos=self.nitro.request(
                'event_query_custom_time',
                time_range=self.time_range,
                start_time=self.start_time,
                end_time=self.end_time,
                #order=self.order, TODO support order
                fields=format_fields_for_query(self.fields),
                filters=self.filters,
                limit=self.limit,
                offset=0, #TODO remove old ref that is useless
                includeTotal=False
                )

        else :
            query_infos=self.nitro.request(
                'event_query',
                time_range=self.time_range,
                #order=self.order, TODO support order
                fields=format_fields_for_query(self.fields),
                filters=self.filters,
                limit=self.limit,
                offset=0, #TODO remove old ref that is useless
                includeTotal=False
                )
        
        log.debug("Waiting for EsmRunningQuery object : "+str(query_infos))
        self._wait_for(query_infos['resultID'])
        events_raw=self._get_events(query_infos['resultID'])

        events=EventManager(alist=events_raw)
        #log.debug("Data loaded : "+str(events))
        
        self.data=events
        return((events,len(events)<self.limit))

    '''
    def load_data(self, *args, **kwargs):
        """
        Specialized EventManager load_data method.  
        Use super load_data implementation.  
        TODO : Use better polymorphism and do not cast here.
        
        Parameters :
        - `*args, **kwargs` : See `msiempy.FilteredQueryList.load_data` and `msiempy.event.EventManager.qry_load_data`
        """
        return EventManager(alist=super().load_data(*args, **kwargs))
        '''
        

    def load_data(self, workers=10, slots=10, delta=None, **kwargs):
        """Load the data from the SIEM into the manager list.  
        Split the query in defferents time slots if the query apprears not to be completed. It wraps around `msiempy.FilteredQueryList.qry_load_data`.    
        If you're looking for `max_query_depth`, it's define at the creation of the `msiempy.FilteredQueryList`.

        Note :  
        If you looking for `load_async`, you should pass this to the constructor method `msiempy.FilteredQueryList` or by setting the attribute manually like `manager.load_asynch=True`
        Only the first query is loaded asynchronously.

        Parameters:  
    
        - `workers` : numbre of parrallels tasks, should be equal or less than the number of slots.  
        - `slots` : number of time slots the query can be divided. The loading bar is 
            divided according to the number of slots  
        - `delta` : exemple : '6h30m', the query will be firstly divided in chuncks according to the time delta read
            with dateutil.  
        - `**kwargs` : Same as `msiempy.event.EventManager.qry_load_data` parameters  

        Returns : `msiempy.event.EventManager`
        """

        items, completed = self.qry_load_data()

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
                    
                else : 
                    times=divide_times(start, end, slots=slots)

                if workers > len(times) :
                    log.warning("The numbre of slots is smaller than the number of workers, only "+str(len(times))+" asynch workers will be used when you could use up to "+str(workers)+". Number of slots should be greater than the number of workers for better performance.")
                
                sub_queries=list()

                for time in times :
                    #Divide the query in sub queries
                    sub_query = copy.copy(self)
                    sub_query.__parent__=self
                    sub_query.compute_time_range=False
                    sub_query.time_range='CUSTOM'
                    sub_query.start_time=time[0].isoformat()
                    sub_query.end_time=time[1].isoformat()
                    sub_query.load_async=False
                    sub_query.query_depth_ttl=self.query_depth_ttl-1
                    
                    sub_queries.append(sub_query)
            
                results = self.perform(EventManager.load_data, sub_queries, 
                    #The sub query is asynch only when it's the first query (root parent)
                    asynch=self.__parent__==None,
                    progress=self.__parent__==None, 
                    message='Loading data from '+self.start_time+' to '+self.end_time+'. In {} slots'.format(len(times)),
                    func_args=dict(slots=slots),
                    workers=workers)

                #Flatten the list of lists in a list
                items=[item for sublist in results for item in sublist]
                
            else :
                if not self.__root_parent__.not_completed :
                    log.warning("The query is not complete... Try to divide in more slots or increase the limit")
                    self.__root_parent__.not_completed=True

        self.data=items
        return(self)

    def _wait_for(self, resultID, sleep_time=0.35):
        """
        Internal method called by qry_load_data
        Wait and sleep - for `sleep_time` duration in seconds -
            until the query is completed
        
        TODO handle SIEM ResultUnavailable error
        """
        log.debug("Waiting for the query to be executed on the SIEM...")
        while True:
            status = self.nitro.request('query_status', resultID=resultID)
            if status['complete'] is True :
                return True
            else :
                time.sleep(sleep_time)

    def _get_events(self, resultID, startPos=0, numRows=None):
        """
        Internal method that will get the query events, 
            called by qry_load_data
        by default, numRows correspond to limit
        """
        
        if not numRows :
            numRows=self.limit
                
        result=self.nitro.request('query_result',
            startPos=startPos,
            numRows=numRows,
            resultID=resultID)

        #Calls a utils function to parse the [columns][rows]
        #   to format into list of dict
        #log.debug("Parsing colums : "+str(result['columns']))
        #log.debug("Parsing rows : "+str(result['rows']))
        if len(result['columns']) != len(set([column['name'] for column in result['columns']])) :
            log.error("You requested duplicated fields, the parsed fields/values results will be missmatched !")
        events=parse_query_result(result['columns'], result['rows'])
        #log.debug("Events parsed : "+str(events))
        return events

    @property
    def __root_parent__(self):
        """
        Internal method that return the first query of the query tree
        """
        if self.__parent__==None:
            return self
        else :
            return self.__parent__.__root_parent__
          
class Event(NitroDict):

    """        
    Default event field keys :  
    - `Rule.msg`  
    - `Alert.SrcPort`  
    - `Alert.DstPort`  
    - `Alert.SrcIP`  
    - `Alert.DstIP`  
    - `Alert.SrcMac`  
    - `Alert.DstMac`  
    - `Alert.LastTime`  
    - `Rule.NormID`  
    - `Alert.DSIDSigID`  
    - `Alert.IPSIDAlertID`  
    
    You can request more fields by passing a list of fields to the `msiempy.event.EventManager` object.
    See msiempy/static JSON files to browse complete list : https://github.com/mfesiem/msiempy/blob/master/static/all_fields.json  
    Prefixes 'Alert.', 'Rule.', etc are optionnal, prefix autocompletion is computed in any case :)

    """
   
    FIELDS_TABLES=["ADGroup",
        "Action",
        "Alert",
        "Asset",
        "AssetGroup",
        "AssetThreat",
        "CaseMgt",
        "CaseOrg",
        "CaseStatus",
        "Class",
        "Connection",
        "DataEnrichment",
        "GeoLoc_ASNGeoDst",
        "GeoLoc_ASNGeoSrc",
        "IOC",
        "IPS",
        "IPSCheck",
        "NDDeviceInterface_NDDevIFDst",
        "NDDeviceInterface_NDDevIFSrc",
        "NDDevice_NDDevIDDst",
        "NDDevice_NDDevIDSrc",
        "OS",
        "Rule",
        "Rule_NDSNormSigID",
        "Tag",
        "TagAsset",
        "ThirdPartyType",
        "Threat",
        "ThreatVendor",
        "TriggeredAlarm",
        "Users",
        "Vulnerability",
        "Zone_ZoneDst",
        "Zone_ZoneSrc",
        ]

   
    DEFAULTS_EVENT_FIELDS=[
        "Rule.msg",
        "Alert.SrcPort",
        "Alert.DstPort", 
        "Alert.SrcIP", 
        "Alert.DstIP", 
        "Alert.SrcMac",
        "Alert.DstMac", 
        "Alert.LastTime",
        "Rule.NormID",
        "Alert.DSIDSigID",
        "Alert.IPSIDAlertID"
        ]
    """Relatively common event fields that could be useful to have.
    """


    def __getitem__(self, key):
        """
        Automatically adding the table name of the field by iterating trought FIELDS_TABLES
        if no '.' is present in the key
        """
        try :
            return collections.UserDict.__getitem__(self, key)
        except (AttributeError, KeyError) : pass

        if '.' not in key :
            for table in self.FIELDS_TABLES :
                try :
                    return collections.UserDict.__getitem__(self, table+'.'+key)
                except (AttributeError, KeyError) : pass
        try :
            return collections.UserDict.__getitem__(self, key)
        except (AttributeError, KeyError) : 
            if key in self.DEFAULTS_EVENT_FIELDS :
                log.error('Some default event fields are missing from SIEM reponse.')
                return 'missing'
            else:
                log.error('The SIEM dict keys are not always the same are the requested fields. check .keys()')
                #Todo : table of corespondance UserIDSrc = BIN(7) etc...
                #Map the table to getitem
                raise
        

    def clear_notes(self):
        """
        Replace the notes by an empty string. Desctructive action.
        """
        self.set_note('', no_date=True)

    def set_note(self, note, no_date=False):
        """
        Set the event's note. Desctructive action.
        """
        the_id = self.data["Alert.IPSIDAlertID"] if "Alert.IPSIDAlertID" in self.data else str(self.data['ipsId']['id'])+'|'+str(self.data["alertId"]) if "alertId" in self.data else None

        if isinstance(the_id, str):

            if len(note) >= 4000:
                log.warning("The note is longer than 4000 characters, only the" 
                            "first 4000 characters will be kept. The maximum" 
                            "accepted by the SIEM is 4096 characters.")
                note=note[:4000]+'\n\n--NOTE HAS BEEN TRUNCATED--'
            
            if no_date==False:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                note = note.replace('"','\\"').replace('\n','\\n')
                note = timestamp + ' - ' + note
            
            self.nitro.request("add_note_to_event_int", 
                id=the_id,
                note=note)
        else :
            log.error("Couldn't set event's note, the event ID hasn't been found.")

    def add_note(self, note):
        """Deprecated, please use set_note() method instead."""
        log.warning(str(DeprecationWarning())+" Please use set_note() method instead.")
        self.set_note(note)
        
    def data_from_id(self, id, use_query=False, extra_fields=[]):
        """
        Load event's data.  

        Parameters :   
        - `id` : The event ID. (i.e. : `144128388087414784|747122896`)  
        - `use_query` : Uses the query module to retreive common event data. Only works with SIEM v 11.2.x.  
        - `extra_fields` : Only when `use_query=True`. Additionnal event fields to load in the query.  
        """
        
        if use_query == True :

            e = EventManager(time_range='CURRENT_YEAR',
                filters=[('IPSIDAlertID',id)],
                compute_time_range=False,
                fields=extra_fields,
                limit=2).load_data()

            if len(e) == 1 :
                return e[0]
            else :
                raise NitroError('Could not load event : '+str(id)+' from query :'+str(e.__dict__)+'. Try with use_query=False.')

        elif use_query == False :
            return self.nitro.request('get_alert_data', id=id)
   
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

        - `filters` : a list of filters, it can be `msiempy.event.FieldFilter` or `msiempy.event.GroupFilter`  
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
    List of possible value type. See `msiempy.event.FieldFilter.add_value`.
    """


    def __init__(self, name, values, operator='IN') :
        """
        Parameters:

        - `name` : field name as string.  
        - `values` : list of values the field is going to be tested againts with the specified orperator.  
        - `orperator` : operator, see `msiempy.event.FieldFilter.POSSIBLE_OPERATORS`.  
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
        Set a list of values by calling `msiempy.FilteredQueryList.add_value()` if value is a 
        `dict` or calls `msiempy.FilteredQueryList.add_basic_value()` if value type is `int`, `float` or `str`.
        Values will always be added to the filter. To remove values, handle directly the `_values` property.

        Example :  
            >>> filter = FieldFilter(name='DstIP',values=['10.1.13.0/24'],operator='IN')
            >>> filter.values=['10.1.14.0/8', {'type':'EsmWatchlistValue', 'watchlist':42}]
            >>> filter.config_dict
            {'type': 'EsmFieldFilter', 
            'field': {'name': 'DstIP'}, 
            'operator': 'IN', 
            'values': [{'type': 'EsmBasicValue', 'value': '10.1.13.0/24'},
                {'type': 'EsmBasicValue', 'value': '10.1.14.0/8'},
                {'type': 'EsmWatchlistValue', 'watchlist': 42}]}
            
        """
        return (self._values)

    @values.setter  
    def values(self, values):
        if isinstance(values, list): 

            for val in values :
                if isinstance(val, dict):
                    self.add_value(**val)

                elif isinstance(val, (int, float, str)) :
                    self.add_basic_value(val)

                else:
                    raise TypeError("Invalid filter type, must be a list, int, float or str")
        
        elif isinstance(values, dict):
            self.add_value(**values)

        elif isinstance(values, (int, float, str)) :
            self.add_basic_value(values)
        
        else :
            raise TypeError("Invalid filter type, must be a list, int, float or str")
        
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
