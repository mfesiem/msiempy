import time
import logging
log = logging.getLogger('msiempy')

from .base import Item, QueryManager, QueryFilter
from .error import NitroError
from .utils import timerange_gettimes, parse_query_result, format_fields_for_query

class EventManager(QueryManager):
    """
    EventManager object.
    Interface to query and manage events.
    Inherits from QueryManager.
    """ 

    #Constants
    TYPE='EVENT'
    GROUPTYPE='NO_GROUP'


    POSSBILE_ROW_ORDER=[
            'ASCENDING',
            'DESCENDING'
    ]

    #Declaring static value containing all the possibles
    # event fields, should be loaded once (when the session start ?)
    _possible_fields = []

    def __init__(self, fields=None, order=None, limit=None, filters=None, compute_time_range=True, *args, **kwargs):
        """
           Params
           ======
           
            fields : list of strings representing all fields you want to apprear in the Events records.
                Get the list of possible fields by calling EventManager.get_possible_fields() method.
                Some defaults fields will always be present unless removed.
            order : Not implemented yet. 
                tuple (direction, field) or a list of filters in the SIEM format.
                will set the first order according to (direction, fields).
                    -> same as using the property setter.
                If you pass a list here, will use the this raw list as the SIEM `order` field.
                Structure must be in correct format
                
                    -> same as setting _order property directly.
            limit : max number of rows per query, by default takes the value in config `default_rows` option.
            filters : list of tuple (field [values])
            compute_time_range : False if you want to send the actualy time_range in parameter for the initial query.
                Defaulted to True cause the query splitting implies computing the time_range anyway.
            
            Examples
            ========
            
            Every init parameters are also properties. E.g. :
            ```
                >>>em=EventManager(fields=['SrcIP','DstIP'],
                        order=('DESCENDING''LastTime'),
                        filters=[('DstIP','4.4.0.0/16','8.8.0.0/16')])
                >>>em.load_data()```
            Equlas :
            ```
                >>>em=EventManager()
                >>>em.fields=['SrcIP','DstIP'],
                >>>em._order=[{  "direction": 'DESCENDING',
                                "field": { "name": 'LastTime' }  }]
                >>>em.filters=[('DstIP','4.4.0.0/16','8.8.0.0/16')]
                >>>em.load_data()```
                
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
        self.limit=self.nitro.config.default_rows if limit is None else int(limit)

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

        #TODO : find a soltuion not to use this stinky tric
        #callign super().filters=filters #https://bugs.python.org/issue14965
        super(self.__class__, self.__class__).filters.__set__(self, filters)

    @property
    def order(self):
        """
        Will return a list of orders representing the what the SIEM is expecting as the 'order'
        """
        return(self._order)

    @order.setter
    def order(self, order):
        """
        The order must be tuple (direction, field).
        Use _order to set with SIEM format.
        """
        
        if type(order) is tuple :
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
        Generates the json SIEM formatted filters for the query by calling reccursive getter : config_dict .
        """
        return([f.config_dict for f in self._filters])

    def add_filter(self, afilter):
        """
        Concrete description of the QueryManager method.
        It can take a tuple(fiels, [values]) or a QueryFilter sub class.
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
        #TODO : find a soltuion not to use this stinky tric
        ##https://bugs.python.org/issue14965
        super(self.__class__, self.__class__).filters.__set__(self,
            [FieldFilter(name='SrcIp', values=['0.0.0.0/0'])])
    
    @property
    def time_range(self):
        """ Same as super class.
            Need to re-declare the time_range getter to be able to define setter.
        """
        return(super().time_range)

    @time_range.setter
    def time_range(self, time_range):
        """
        Set the time range of the query to the specified string value.
        Trys if compute_time_range is True - by default it is - to get a 
            start and a end time with utils.timerange_gettimes()
        """
        if time_range and self.compute_time_range :
            try :
                times = timerange_gettimes(time_range)
                self._time_range='CUSTOM'
                self._start_time=times[0]
                self._end_time=times[1]
            # timerange_gettimes raises AttributeError until
            # all timeranges are supported
            except AttributeError as err:
                log.warning(err)
                #TODO : find a soltuion not to use this stinky tric
                #Calling super().time_range=time_range
                #https://bugs.python.org/issue14965
                super(self.__class__, self.__class__).time_range.__set__(self, time_range)
            except :
                raise
        else :
            #TODO : find a soltuion not to use this stinky tric
            super(self.__class__, self.__class__).time_range.__set__(self, time_range)

    def get_possible_fields(self):
        """
        Indicate a list of possible fields that you can request in a query.
        The list is loaded from the SIEM.
        """
        return self.nitro.request('get_possible_fields', type=self.TYPE, groupType=self.GROUPTYPE)

    def _load_data(self):
        """"
            Internal helper method to execute the query and load the data.
            Returns a list of Events, the status of the query.
            return a tuple (items, completed).
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

    def load_data(self):
        return EventManager(alist=super().load_data())

    def _wait_for(self, resultID, sleep_time=0.35):
        """
        Wait and sleep - for `sleep_time` duration in seconds - until the query is completed
        #TODO handle SIEM ResultUnavailable error
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
        Internal method that will get the query events.
        numRows correspond to limit/page_size
        """
        if not numRows :
            numRows=self.limit
                
        result=self.nitro.request('query_result',
            startPos=startPos,
            numRows=numRows,
            resultID=resultID)

        events=parse_query_result(result['columns'], result['rows'])
        return events
        
    
class Event(Item):
    """
    Event
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
        "SrcPort",
        "DstPort", 
        "SrcIP", 
        "DstIP", 
        "SrcMac",
        "DstMac", 
        "LastTime",
        "NormID",
        "DSIDSigID",
        "IPSID",
        "AlertID",
        "UserIDSrc",
        "UserIDDst",
        "CommandID"
        ]

    def __getitem__(self, key):
        """
        Automatically adding the table name of the field 
            if no '.' is present in the key
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

    def clear_notes(self):
        NotImplementedError()

    def add_note(self, note):
        NotImplementedError()

class GroupFilter(QueryFilter):
    """
        Based on EsmFilterGroup
    """

    def __init__(self, *filters, logic='AND') :
        super().__init__()
        
        #Declaring attributes
        self.filters=filters
        self.logic=logic

    def config_dict(self):
        return({
            "type": "EsmFilterGroup",
            "filters": [f.config_dict() for f in self.filters],
            "logic":self.logic
            })
        
class FieldFilter(QueryFilter):
    """
    Based on EsmFieldFilter
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

    POSSIBLE_VALUE_TYPES=[
            {'type':'EsmWatchlistValue',    'key':'watchlist'},
            {'type':'EsmVariableValue',     'key':'variable'},
            {'type':'EsmBasicValue',        'key':'value'},
            {'type':'EsmCompoundValue',     'key':'values'}]


    def __init__(self, name, values, operator='IN') :
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
        return ({
            "type": "EsmFieldFilter",
            "field": {"name": self.name},
            "operator": self.operator,
            "values": self.values
            })

    @property
    def name(self):
        return (self._name)
    
    @property
    def operator(self):
        return (self._operator)

    @property
    def values(self):
        return (self._values)

    @name.setter
    def name(self, name):
        
        if True : # Not checking dynamically the velidity of the fields cause makes too much of unecessary requests any(f.get('name', None) == name for f in self._possible_filters):
            self._name = name
        else:
            raise AttributeError("Illegal value for the "+name+" field. The filter must be in :"+str([f['name'] for f in self._possible_filters]))
       

    @operator.setter
    def operator(self, operator):
        try:
            if operator in self.POSSIBLE_OPERATORS :
                self._operator = operator
            else:
                raise AttributeError("Illegal value for the filter operator "+operator+". The operator must be in "+str(self.POSSIBLE_OPERATORS))
        except:
            raise
        
    def add_value(self, type, **args):
        """
        Args could be :
            **{'type':'EsmWatchlistValue',    'watchlist':1}
            **{'type':'EsmVariableValue',     'variable':1}
            **{'type':'EsmBasicValue',        'value':'a value'}
            **{'type':'EsmCompoundValue',     'values':['']}
        """
        try:
            type_template=None
            
            for possible_value_type in self.POSSIBLE_VALUE_TYPES :
                if possible_value_type['type'] == type :
                    type_template=possible_value_type
                    if type != 'EsmBasicValue' :
                        log.warning("Filtering query with other type of filter than 'EsmBasicValue' is not tested.")                            
                    break

            if type_template is not None :
                if type_template['key'] in args :
                    value = args[type_template['key']]
                    if type == 'EsmBasicValue' :
                        value=str(value)
                       # log.debug('Adding a basic value to filter ('+self.text+') : '+value)

                    self._values.append({'type':type, type_template['key']:value})
                    #log.debug('The value was appended to the list: '+str(self))
                else: raise KeyError ('The valid key value parameter is not present')
            else: raise KeyError ('Impossible filter')
        except KeyError as err:
            raise AttributeError("You must provide a valid named parameters containing the type and values for this filter. The type/keys must be in "+str(self.POSSIBLE_VALUE_TYPES)+"Can't be type="+str(type)+' '+str(args)+". Additionnal indicator :"+str(err) )

    def add_basic_value(self, value):
        self.add_value(type='EsmBasicValue', value=value)

    @values.setter
    def values(self, values):
        for val in values :
            if isinstance(val, dict):
                self.add_value(**val)

            elif isinstance(val, (int, float, str)) :
                self.add_basic_value(val)
