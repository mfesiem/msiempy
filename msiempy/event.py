"""Provide event management.
"""

import time
import collections
import datetime
import logging
log = logging.getLogger('msiempy')

from . import NitroDict, NitroError
from .query import FilteredQueryList, FieldFilter, GroupFilter, QueryFilter
from .utils import timerange_gettimes, parse_query_result, format_fields_for_query

class EventManager(FilteredQueryList):
    """Interface to query and manage events.
    Inherits from `msiempy.query.FilteredQueryList`.
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

    def __init__(self, fields=None, order=None, limit=None, filters=None, compute_time_range=True, *args, **kwargs):
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
        - `filters` : list of filters. A filter can be a `tuple(field, [values])` or it can be a `msiempy.query.QueryFilter`
        if you wish to use advanced filtering.
        - `compute_time_range` : False if you want to send the actualy time_range in parameter for the initial query.
            Defaulted to True cause the query splitting implies computing the time_range anyway.
        - `*args, **kwargs` : Parameters passed to `msiempy.query.FilteredQueryList`
           
            
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
        self.limit=self.requests_size if limit is None else int(limit)
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
    def table_colums(self):
        return Event.DEFAULTS_EVENT_FIELDS

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
        JSON SIEM formatted filters for the query by calling reccursively : `msiempy.query.QueryFilter.config_dict`.
        See `msiempy.query.FilteredQueryList.filters`.
        """
        return([f.config_dict for f in self._filters])

    def add_filter(self, afilter):
        """
        Concrete description of the `msiempy.query.FilteredQueryList` method.
        It can take a `tuple(fiels, [values])` or a `msiempy.query.QueryFilter` subclass.
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
        """Re-implemented the `msiempy.query.FilteredQueryList.time_range` to have better control on the property setter.
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

    def _load_data(self, workers):
        """"
            Concrete helper method to execute the query and load the data : 
                -> Submit the query -> wait -> get the events -> parse -
                    -> convert to EventManager ->  set self.data and return 
            Returns a tuple ( list of Events(1) ,the status of the query )
                      tuple (items, completed).
            
            (1) aka EventManager
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

    def load_data(self, **kwargs):
        """
        Specialized EventManager load_data method.
        Use super load_data implementation.
        You could decide not to use the splitting feature by 
            calling directly _load_data() 
            kwargs are passed to super().load_data()
        """
        return EventManager(alist=super().load_data(**kwargs))

    def _wait_for(self, resultID, sleep_time=0.35):
        """
        Internal method called by _load_data
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
            called by _load_data
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
          
class Event(NitroDict):
    """        
    Default event field keys :  
    - `Rule.msg`
    - `Alert.SrcPort`
    - `Alert.DstPort`
    - `Alert.SrcIP`
    - `Alert.DstIP`
    - `SrcMac`
    - `Alert.DstMac`
    - `Alert.LastTime`
    - `Rule.NormID`
    - `Alert.DSIDSigID`
    - `Alert.IPSIDAlertID`
    
    You can request more fields by passing a list of fields to the `msiempy.event.EventManager` object.
    See msiempy/static JSON files to browse complete list : https://github.com/mfesiem/msiempy/blob/master/static/all_fields.json

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
        Not working. Skipping.
        TODO try with collections.UserDict.__getitem__(self, key)
        """

        return super().__getitem__(key)
        """
        if '.' not in key :
            for table in self.FIELDS_TABLES :
                try :
                    return super().__getitem__(table+'.'+key)
                except (AttributeError, KeyError) : pass
        try :
            return super().__getitem__(key)
        except (AttributeError, KeyError) : 
            if key in self.DEFAULTS_EVENT_FIELDS :
                log.error('Some default event fields are missing from SIEM reponse.')
                return 'missing'
            else:
                log.error('The SIEM dict keys are not always the same are the requested fields. check .keys()')
                raise
        """

    def clear_notes(self):
        """
        Desctructive action.
        Replace the notes by an empty string. 
        """
        NotImplementedError()

    def add_note(self, note):
        """
        Desctructive action. It's actually going to replace the note !
        Add a new note in the note field.
        """
        if len(note) >= 4000:
            log.warning("The note is longer than 4000 characters, only the first 4000 characters will be kept. The maximum accepted by the SIEM is 4096 characters.")
            note=note[:4000]+'\n\n----- MAXIMUM NOTE LENGHT REACHED, THE NOTE HAS BEEN TRUNCATED (sorry) -----'

        self.nitro.request("add_note_to_event", 
            id=self.data["Alert.IPSIDAlertID"],
            note="NOTE (msiempy-{}) : \\n{}".format(
                str(datetime.datetime.now()),
                note.replace('"','\\"').replace('\n','\\n')))
        
    def data_from_id(self, id):
        """EsmAlertData wrapper"""
        return self.nitro.request('get_alert_data', id=id)