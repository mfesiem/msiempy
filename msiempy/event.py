import time
import logging
log = logging.getLogger('msiempy')

from .base import Item, QueryManager, QueryFilter
from .error import NitroError
from .utils import timerange_gettimes, parse_query_result, format_fields_for_query

class EventManager(QueryManager):
    """
    EventManage
    """ 

    #Constants
    TYPE='EVENT'
    GROUPTYPE='NO_GROUP'

    #Declaring static value containing all the possibles
    # event fields, should be loaded once (when the session start ?)
    _possible_fields = []

    def __init__(self, fields=None, order=None , *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.limit=self.nitro.config.default_rows

        #Declaring attributes
        self._filters=list()

        self.fields=set(Event.DEFAULTS_EVENT_FIELDS+fields)
        self.reverse=bool()

        if isinstance(order, dict):
            self._order=order
        else:
            self._order=[{
                "direction": None,
                "field": {
                    "name": None
                    }
                }]
            self.order=order

    @order.setter
    def order(self, order):
        #tuple (direction, field)
        #TODO check valid value
        if type(order) is tuple :
            self._order[0]['direction']=order[0]
            self._order[0]['field']['name']=order[1]

    @property
    def filters(self):
        return([f.config_dict() for f in self._filters])

    def add_filter(self, fil):
        if type(fil) is tuple :
            self._filters.append(FieldFilter(*fil))

        elif isinstance(fil, QueryFilter) :
            self._filters.append(fil)
        
        else :
            raise NitroError("Sorry the filters must be either a tuple(fiels, [values]) or a QueryFilter sub class.")

    def clear_filters(self):
        self.filters = [FieldFilter(name='AvgSeverity', operator='GREATER_THAN' , values=[-1])]

    @time_range.setter
    def time_range(self, time_range):
        """
        Set the time range of the query to the specified string value.
        Trys by default to cut get a start and a end time with timerange_gettimes
        """
        try :
            times = timerange_gettimes(time_range)
            self._time_range='CUSTOM'
            self._start_time=times[0]
            self._end_time=times[1]
        # timerange_gettimes raises AttributeError until
        # all timeranges are supported
        except AttributeError as err:
            log.warning(err)
            #Calling super().time_range=time_range
            #https://bugs.python.org/issue14965
            super(self.__class__, self.__class__).time_range.__set__(self, time_range)
        except :
            raise

    def _load_data(self):
        """"
            Execute the query.
            Returns a list of Events, the status of the query.
            return a tuple (items, completed)
        """
        query_infos=dict()

        if self.time_range is 'CUSTOM' :
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
        events=EventManager(self._get_events(query_infos['resultID']))
        self.data+=events
        return((events,len(events)<self.limit))

    def _wait_for(self, resultID):
        log.debug("Waiting for the query to be executed on the SIEM...")
        while True:
            status = self.nitro.request('query_status', resultID=resultID)
            if status['complete'] is True :
                return True
            else :
                time.sleep(0.35)

    def _get_events(self, resultID, startPos=0, numRows=None):
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
        "DSIDSigID",
        "msg",
        "SrcPort",
        "DstPort", 
        "SrcIP", 
        "DstIP", 
        "SrcMac",
        "DstMac", 
        "LastTime",
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
        self._filters=filters
        self._logic=logic

    def config_dict(self):
        return({
            "type": "EsmFilterGroup",
            "filters": [f.config_dict() for f in self._filters],
            "logic":self._logic
            })
        
class FieldFilter(QueryFilter):
    """
    Based on EsmFieldFilter
    """

    def __init__(self, name, values, operator='IN') :
        super().__init__()
        #Declaring attributes
        self._name=str()
        self._operator=str()
        self._values=list()

        self.name = name
        self.operator = operator
        self.values = values

    def config_dict(self):
        return ({
            "type": "EsmFieldFilter",
            "field": {"name": self._name},
            "operator": self._operator,
            "values": self._values
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
            raise NitroError("Illegal value for the "+name+" field. The filter must be in :"+str([f['name'] for f in self._possible_filters]))
       

    @operator.setter
    def operator(self, operator):
        try:
            if operator in POSSIBLE_OPERATORS :
                self._operator = operator
            else:
                raise NitroError("Illegal value for the filter operator "+operator+". The operator must be in "+str(POSSIBLE_OPERATORS))
        except:
            raise
        
    def add_value(self, type, **args):
        """
        Please refer to the EsmFilterValue documentation
        """
        try:
            type_template=None
            for possible_value_type in POSSIBLE_VALUE_TYPES :
                if possible_value_type['type'] == type :
                    type_template=possible_value_type
                    break

            if type_template is not None :
                if type_template['key'] in args :
                    self._values.append({'type':type, type_template['key']:args[type_template['key']]})

                else:
                    raise NitroError("You must provide a valid named parameter containing the value(s). The key must be in "+str(POSSIBLE_VALUE_TYPES))

            else:
                raise NitroError("Illegal value type for the value filter. The type must be in "+str(POSSIBLE_VALUE_TYPES))
        except:
            raise

    def add_basic_value(self, value):
        self.add_value(type='EsmBasicValue', value=str(value))

    @values.setter
    def values(self, values):
        for v in values :
            if isinstance(v, dict):
                self.add_value(**v)

            elif isinstance(v, (int, float, str)) :
                self.add_basic_value(v)