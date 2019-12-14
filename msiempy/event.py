"""Provide event management.
"""

import time
import json
import abc
import collections
import logging
import copy
from datetime import datetime, timedelta
log = logging.getLogger('msiempy')

from . import NitroDict, NitroError, FilteredQueryList
from .__utils__ import timerange_gettimes, parse_query_result, format_fields_for_query, divide_times, parse_timedelta

class EventManager(FilteredQueryList):
    """Interface to query and manage events.  
    Inherits from `msiempy.FilteredQueryList`.

    Arguments:  

    - `fields` : list of strings representing all fields you want to apprear in the Events records.
        Get the list of possible fields by calling `msiempy.event.EventManager.get_possible_fields()` method or see `msiempy.event.Event`.
        Some default fields will be present. 
    - `order` : `tuple ((direction, field))`. Direction can be 'ASCENDING' or 'DESCENDING'.
    - `limit` : max number of rows per query.
    - `filters` : list of filters. A filter can be a `tuple(field, [values])` or it can be a `msiempy.event._QueryFilter` if you wish to use advanced filtering.
    - `time_range` : Query time range. String representation of a time range.  
    - `start_time` : Query starting time, can be a `string` or a `datetime` object. Parsed with `dateutil`.  
    - `end_time` : Query endding time, can be a `string` or a `datetime` object. Parsed with `dateutil`.  
    """ 

    #Constants
    #TODO Try grouped queries !
    TYPE='EVENT'
    """EVENT: Flow query or other are not implemented"""
    GROUPTYPE='NO_GROUP'
    """NO_GROUP: Group query is not implemented"""
    POSSBILE_ROW_ORDER=[
            'ASCENDING',
            'DESCENDING'
    ]
    """`ASCENDING` or `DESCENDING`"""

    # Declaring static value containing all the possibles
    # event fields, should be loaded once (when the session start ?)
    _possible_fields = []

    def __init__(self, *args, fields=None, 
        order=None, limit=500, filters=None, 
        __parent__=None, **kwargs):
        #Calling super constructor : time_range set etc...
        super().__init__(*args, **kwargs)

        #Store the query parent 
        self.__parent__=__parent__

        #Declaring attributes
        self._filters=list()
        
        #Setting the default fields Adds the specified fields and make sure there is no duplicates
        #print('{}\n DEBUG FIELDS : {}'.format(locals(), fields))
        if isinstance(fields, list):self.fields=set(Event.DEFAULTS_EVENT_FIELDS+fields)
        else:self.fields=Event.DEFAULTS_EVENT_FIELDS

        #Setting limit according to config or limit argument
        #TODO Try to load queries with a limit of 10k and get result as chucks of 500 with starPost nbRows
        #   and compare efficiency
        self.limit=int(limit)
        
        self.order=order

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
        The `order` must be tuple (direction, field).
        """
        return((self._order_direction, self._order_field))

    @order.setter
    def order(self, order):
        if order:
            try:
                if order[0] not in self.POSSBILE_ROW_ORDER :
                    raise AttributeError('Order direction must be in '+str(self.POSSBILE_ROW_ORDER))

                self._order_direction = order[0]
                self._order_field = order[1]
            except IndexError:
                raise ValueError('Order must be tuple (direction, field).')
        else:
            self._order_direction = 'DESCENDING'
            self._order_field = 'LastTime'
    @property
    def filters(self):
        """
        JSON SIEM formatted filters for the query by calling reccursively : `msiempy.event._QueryFilter.config_dict`.
        See `msiempy.FilteredQueryList.filters`.
        """
        return([dict(f) for f in self._filters])

    def add_filter(self, afilter):
        """
        Concrete description of the `msiempy.FilteredQueryList` method.
        It can take a `tuple(fiels, [values])` or a `msiempy.event._QueryFilter` subclass.
        """
        if isinstance(afilter, tuple) :
            self._filters.append(FieldFilter(afilter[0], afilter[1]))

        elif isinstance(afilter, _QueryFilter) :
            self._filters.append(afilter)
        
        else :
            raise NitroError("Sorry the filters must be either a tuple(fiels, [values]) or a _QueryFilter sub class.")

    def clear_filters(self):
        """
        Replace all filters by a non filtering rule.
        Acts like the is not filters.
        """ 
        self._filters=[FieldFilter('SrcIP', ['0.0.0.0/0',])]

    def get_possible_fields(self):
        """
        Indicate a list of possible fields that you can request in a query.
        The list is loaded from the SIEM.
        """
        return self.nitro.request('get_possible_fields', type=self.TYPE, groupType=self.GROUPTYPE)

    def qry_load_data(self, retry=2, wait_timeout_sec=120):
        """
        Concrete helper method to execute the query and load the data :  
            -> Submit the query  
            -> Wait the query to be executed  
            -> Get and parse the events  

        Arguments:

        - `retry` (`int`): number of time the query can be failed and retied
        - `wait_timeout_sec` (`int`): wait timeout in seconds

        Returns : `tuple` : (( `msiempy.event.EventManager`, Status of the query (completed?) `True/False` ))

        Can raise `msiempy.NitroError`: 

            - Query wait timeout -> You might want to change the value of `wait_timeout_sec` argument !
            - Other errors
        """
        query_infos=dict()

        #Queries api calls are very different if the time range is custom.
        if self.time_range == 'CUSTOM' :
            query_infos=self.nitro.request(
                'event_query_custom_time',
                time_range=self.time_range,
                start_time=self.start_time,
                end_time=self.end_time,
                order_direction=self._order_direction,
                order_field=self._order_field,
                fields=format_fields_for_query(self.fields),
                filters=self.filters,
                limit=self.limit,
                offset=0,
                includeTotal=False
                )

        else :
            query_infos=self.nitro.request(
                'event_query',
                time_range=self.time_range,
                order_direction=self._order_direction,
                order_field=self._order_field,
                fields=format_fields_for_query(self.fields),
                filters=self.filters,
                limit=self.limit,
                offset=0,
                includeTotal=False
                )
        
        log.debug("Waiting for EsmRunningQuery object : "+str(query_infos))
        try:
            self._wait_for(query_infos['resultID'], wait_timeout_sec)
            events_raw=self._get_events(query_infos['resultID'])
        except NitroError as error :
            if retry >0 and any(match in str(error) for match in ['ResultUnavailable','UnknownList', 'Query wait timeout']):
                log.warning('Retring after: '+str(error))
                return self.qry_load_data(retry=retry-1)
            else: raise

        events=EventManager(alist=events_raw)
        self.data=events
        return((events,len(events)<self.limit))

    def load_data(self, workers=10, slots=10, delta=None, max_query_depth=0, **kwargs):
        """Load the data from the SIEM into the manager list.  
        Split the query in defferents time slots if the query apprears not to be completed.  
        Wraps around `msiempy.FilteredQueryList.qry_load_data`.    

        Note: Only the first query is loaded asynchronously.

        Arguments:  
    
        - `workers` : numbre of parrallels tasks, should be equal or less than the number of slots.  
        - `slots` : number of time slots the query can be divided. The loading bar is 
            divided according to the number of slots  
        - `delta` : exemple : '6h30m', the query will be firstly divided in chuncks according to the time delta read
            with dateutil.  
        - `max_query_depth` : maximum number of supplement reccursions of division of the query times
        Meaning, if limit=500, slots=5 and max_query_depth=3, then the maximum capacity of 
        the list is (500*5)*(500*5)*(500*5) = 15625000000
        - `retry` (`int`): number of time the query can be failed and retied
        - `wait_timeout_sec` (`int`): wait timeout in seconds


        Returns : `msiempy.event.EventManager`
        """

        items, completed = self.qry_load_data()

        if not completed :
            #If not completed the query is split and items aren't actually used

            if max_query_depth > 0 :
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

                for time in times : #reversed(times) :
                    #Divide the query in sub queries
                    sub_query = EventManager(fields=self.fields, 
                        order=self.order, 
                        limit=self.limit,
                        filters=self._filters,
                        time_range='CUSTOM',
                        start_time=time[0].isoformat(),
                        end_time=time[1].isoformat(),

                         __parent__=self
                        )
                    
                    sub_queries.append(sub_query)
            
                results = self.perform(EventManager.load_data, sub_queries, 
                    #The sub query is asynch only when it's the first query (root parent)
                    asynch=self.__parent__==None,
                    progress=self.__parent__==None, 
                    message='Loading data from '+start+' to '+end+'. In {} slots'.format(len(times)),
                    func_args=dict(slots=slots, max_query_depth=max_query_depth-1),
                    workers=workers)

                #Flatten the list of lists in a list
                items=[item for sublist in results for item in sublist]
                
            else :
                if not self.__root_parent__.not_completed :
                    log.warning("The query is not complete... Try to divide in more slots or increase the limit")
                    self.__root_parent__.not_completed=True

        self.data=items
        return(self)

    def _wait_for(self, resultID, wait_timeout_sec, sleep_time=0.2):
        """
        Internal method called by qry_load_data
        Wait and sleep - for `sleep_time` duration in seconds -
            until the query is completed or retry countdown arrives at zero.    
        
        Return: `True`  

        Raises: 

        - `msiempy.NitroError`: 'ResultUnavailable' error some times...
        - `msiempy.NitroError`: 'Query wait timeout'
        """
        # time_out=parse_timedelta(wait_timeout).total_seconds()
        # retry = wait_timeout_sec / sleep_time

        begin=datetime.now()
        timeout_delta=timedelta(seconds=wait_timeout_sec)

        log.debug("Waiting for the query to be executed on the SIEM...")
        
        while datetime.now()-timeout_delta < begin :
            status = self.nitro.request('query_status', resultID=resultID)
            if status['complete'] is True :
                return True
            else :
                time.sleep(sleep_time)
            # retry=retry-1
        raise NitroError("Query wait timeout. resultID={}, sleep_time={}, wait_timeout_sec={}".format(
            resultID, sleep_time, wait_timeout_sec))

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

    def get_possible_filters(self):
        """
        Return all the fields that you can filter on in a query.
        """
        return(self.nitro.request('get_possible_filters'))
          
class Event(NitroDict):
    """        
    Dictionary keys :  

    - `Rule.msg`  
    - `Alert.LastTime`  
    - `Alert.IPSIDAlertID`  
    - and others...  

    You can request more fields by passing a list of fields to the `msiempy.event.EventManager` object. 
    `msiempy.event.Event.REGULAR_EVENT_FIELDS` offer a base list of regular fields that may be useful.
    See msiempy/static JSON files to browse complete list : https://github.com/mfesiem/msiempy/blob/master/static/all_fields.json  
    You can also use this script to dinamically print the available fields and filters : https://github.com/mfesiem/msiempy/blob/master/samples/dump_all_fields.py  
    Prefixes `Alert.`, `Rule.`, etc are optionnal, prefix autocompletion is computed in any case within the `__getitem__` method ;)  

    Arguments:

    - `adict`: Event parameters  
    - `id`: The event `IPSIDAlertID` to instanciate. Will load informations
    """
   
    FIELDS_TABLES=[
        "Alert",
        "Rule",
        "ADGroup",
        "Action",
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
    """List of internal fields table : `Rule`,`Alert`,etc.
    """

    # Minimal default query fields
    DEFAULTS_EVENT_FIELDS=[
        "Rule.msg",
        "Alert.LastTime",
        "Alert.IPSIDAlertID"]
    """Always present when using `msiempy.event.EventManager` querying :  
        `Rule.msg`  
        `Alert.LastTime`  
        `Alert.IPSIDAlertID`
    """
    # Regular query fields
    REGULAR_EVENT_FIELDS=[
        "Rule.msg",
        "Alert.SrcIP",
        "Alert.DstIP", 
        "Alert.SrcMac",
        "Alert.DstMac",
        "Rule.NormID",
        "HostID",
        "UserIDSrc",
        "ObjectID",
        "Alert.Severity",
        "Alert.LastTime",
        "Alert.DSIDSigID",
        "Alert.IPSIDAlertID"]
    """
        `Rule.msg`  
        `Alert.SrcIP`  
        `Alert.DstIP`   
        `Alert.SrcMac`  
        `Alert.DstMac`  
        `Rule.NormID`  
        `HostID`  
        `UserIDSrc`  
        `ObjectID`  
        `Alert.Severity`  
        `Alert.LastTime`  
        `Alert.DSIDSigID`  
        `Alert.IPSIDAlertID` 
    """
    
    SIEM_FIELDS_MAP = {
        'ASNGeoDst': 'Alert.ASNGeoDst',
        'ASNGeoSrc': 'Alert.ASNGeoSrc',
        'Access_Mask': 'Alert.65622',
        'Access_Privileges': 'Alert.4259883',
        'Access_Resource': 'Alert.65555',
        'Action': 'Alert.Action',
        'Action.Name': 'Action.Name',
        'Agent_GUID': 'Alert.262162',
        'AlertID': 'Alert.AlertID',
        'Analyzer_DAT_Version': 'Alert.262170',
        'AppID': 'Alert.BIN(1)',
        'AppIDCat': 'Alert.AppIDCat',
        'App_Layer_Protocol': 'Alert.65615',
        'Application_Protocol': 'Alert.BIN(9)',
        'Area': 'Alert.65576',
        'Attacker_IP': 'Alert.262175',
        'Attribute_Type': 'Alert.65621',
        'Authentication_Type': 'Alert.65618',
        'Authoritative_Answer': 'Alert.BIN(20)',
        'AvgSeverity': 'Alert.AvgSeverity',
        'Bcc': 'Alert.4259847',
        'Caller_Process': 'Alert.65587',
        'Catalog_Name': 'Alert.65556',
        'Category': 'Alert.65540',
        'Cc': 'Alert.4259846',
        'Class.Name': 'Class.Name',
        'Class.Priority': 'Class.Priority',
        'Client_Version': 'Alert.4259853',
        'CnC_Host': 'Alert.65628',
        'CommandID': 'Alert.BIN(2)',
        'CommandIDCat': 'Alert.CommandIDCat',
        'Confidence': 'Alert.4456458',
        'Contact_Name': 'Alert.BIN(15)',
        'Contact_Nickname': 'Alert.BIN(16)',
        'Cookie': 'Alert.4259850',
        'Creator_Name': 'Alert.65551',
        'DAT_Version': 'Alert.262165',
        'DB2_Plan_Name': 'Alert.65557',
        'DNS - Class': 'Alert.21364737',
        'DNS - Class_Name': 'Alert.38141953',
        'DNS - Query': 'Alert.122028033',
        'DNS - Response_Code': 'Alert.88473601',
        'DNS - Response_Code_Name': 'Alert.105250817',
        'DNS - Type': 'Alert.54919169',
        'DNS - Type_Name': 'Alert.71696385',
        'DNS_Class': 'Alert.BIN(18)',
        'DNS_Name': 'Alert.4259867',
        'DNS_Server_IP': 'Alert.262178',
        'DNS_Type': 'Alert.BIN(17)',
        'DSID': 'Alert.DSID',
        'DSIDSigID': 'Alert.DSIDSigID',
        'Database_GUID': 'Alert.262169',
        'Database_ID': 'Alert.65569',
        'Database_Name': 'Alert.BIN(8)',
        'Datacenter_ID': 'Alert.65602',
        'Datacenter_Name': 'Alert.65603',
        'Delivery_ID': 'Alert.65550',
        'Description': 'Alert.4259873',
        'Destination_Directory': 'Alert.65592',
        'Destination_Filename': 'Alert.4259852',
        'Destination_Hostname': 'Alert.65539',
        'Destination_Logon_ID': 'Alert.65584',
        'Destination_Network': 'Alert.65573',
        'Destination_UserID': 'Alert.65567',
        'Destination_Zone': 'Alert.65542',
        'Detection_Method': 'Alert.65599',
        'Device_Action': 'Alert.65594',
        'Device_Confidence': 'Alert.262179',
        'Device_IP': 'Alert.262154',
        'Device_Port': 'Alert.262155',
        'Device_URL': 'Alert.4259886',
        'Direction': 'Alert.BIN(30)',
        'Directory': 'Alert.65591',
        'DomainID': 'Alert.BIN(3)',
        'DomainIDCat': 'Alert.DomainIDCat',
        'DstIP': 'Alert.DstIP',
        'DstMac': 'Alert.DstMac',
        'DstPort': 'Alert.DstPort',
        'End_Page': 'Alert.4456451',
        'Engine_List': 'Alert.4259887',
        'EventCount': 'Alert.EventCount',
        'Event_Class': 'Alert.65545',
        'External_Application': 'Alert.65552',
        'External_DB2_Server': 'Alert.65553',
        'External_Device_ID': 'Alert.65607',
        'External_Device_Name': 'Alert.65608',
        'External_Device_Type': 'Alert.65606',
        'External_EventID': 'Alert.262156',
        'External_Hostname': 'Alert.65575',
        'External_SessionID': 'Alert.65582',
        'External_SubEventID': 'Alert.262158',
        'FTP_Command': 'Alert.65559',
        'Facility': 'Alert.65577',
        'File_Hash': 'Alert.262159',
        'File_ID': 'Alert.65620',
        'File_Operation': 'Alert.BIN(12)',
        'File_Operation_Succeeded': 'Alert.BIN(13)',
        'File_Path': 'Alert.4259877',
        'File_Type': 'Alert.65558',
        'Filename': 'Alert.4259843',
        'FirstTime': 'Alert.FirstTime',
        'Flow': 'Alert.Flow',
        'FlowID': 'Alert.FlowID',
        'From': 'Alert.4259844',
        'From_Address': 'Alert.4259875',
        'GUIDDst': 'Alert.GUIDDst',
        'GUIDSrc': 'Alert.GUIDSrc',
        'GeoLoc_ASNGeoDst.Latitude': 'GeoLoc_ASNGeoDst.Latitude',
        'GeoLoc_ASNGeoDst.Longitude': 'GeoLoc_ASNGeoDst.Longitude',
        'GeoLoc_ASNGeoDst.Msg': 'GeoLoc_ASNGeoDst.Msg',
        'GeoLoc_ASNGeoDst.XCoord': 'GeoLoc_ASNGeoDst.XCoord',
        'GeoLoc_ASNGeoDst.YCoord': 'GeoLoc_ASNGeoDst.YCoord',
        'GeoLoc_ASNGeoSrc.Latitude': 'GeoLoc_ASNGeoSrc.Latitude',
        'GeoLoc_ASNGeoSrc.Longitude': 'GeoLoc_ASNGeoSrc.Longitude',
        'GeoLoc_ASNGeoSrc.Msg': 'GeoLoc_ASNGeoSrc.Msg',
        'GeoLoc_ASNGeoSrc.XCoord': 'GeoLoc_ASNGeoSrc.XCoord',
        'GeoLoc_ASNGeoSrc.YCoord': 'GeoLoc_ASNGeoSrc.YCoord',
        'Grid_Master_IP': 'Alert.262153',
        'Group_Name': 'Alert.65614',
        'Handheld_ID': 'Alert.262168',
        'Handle_ID': 'Alert.262160',
        'Hash': 'Alert.65624',
        'Hash_Type': 'Alert.65625',
        'Hops': 'Alert.4456459',
        'HostID': 'Alert.BIN(4)',
        'HostIDCat': 'Alert.HostIDCat',
        'IPS.Name': 'IPS.Name',
        'IPSID': 'Alert.IPSID',
        'IPSIDAlertID': 'Alert.IPSIDAlertID',
        'Incident_ID': 'Alert.262173',
        'Incoming_ID': 'Alert.65574',
        'Instance_GUID': 'Alert.262161',
        'Interface': 'Alert.BIN(29)',
        'Interface_Dest': 'Alert.65604',
        'Job_Name': 'Alert.4259854',
        'Job_Type': 'Alert.65560',
        'LPAR_DB2_Subsystem': 'Alert.65562',
        'Language': 'Alert.4259855',
        'LastTime': 'Alert.LastTime',
        'LastTime_usec': 'Alert.LastTime_usec',
        'Local_User_Name': 'Alert.4259860',
        'Logical_Unit_Name': 'Alert.65561',
        'Logon_Type': 'Alert.65580',
        'Mail_ID': 'Alert.65548',
        'Mailbox': 'Alert.65590',
        'Mainframe_Job_Name': 'Alert.65568',
        'Malware_Insp_Action': 'Alert.65570',
        'Malware_Insp_Result': 'Alert.65571',
        'Management_Server': 'Alert.65581',
        'Message_ID': 'Alert.65547',
        'Message_Text': 'Alert.4259842',
        'Method': 'Alert.BIN(11)',
        'NAT_Details': 'Alert.262146',
        'NTP_Client_Mode': 'Alert.BIN(25)',
        'NTP_Offset_To_Monitor': 'Alert.4456457',
        'NTP_Opcode': 'Alert.BIN(28)',
        'NTP_Request': 'Alert.BIN(27)',
        'NTP_Server_Mode': 'Alert.BIN(26)',
        'New_Reputation - ATD_File': 'Alert.54919172',
        'New_Reputation - GTI_Cert': 'Alert.71696388',
        'New_Reputation - GTI_File': 'Alert.21364740',
        'New_Reputation - TIE_Cert': 'Alert.88473604',
        'New_Reputation - TIE_File': 'Alert.38141956',
        'New_Value': 'Alert.4259885',
        'Num_Copies': 'Alert.4456449',
        'ObjectID': 'Alert.BIN(5)',
        'ObjectIDCat': 'Alert.ObjectIDCat',
        'Object_GUID': 'Alert.262176',
        'Object_Type': 'Alert.BIN(10)',
        'Old_Reputation - ATD_File': 'Alert.54919171',
        'Old_Reputation - GTI_Cert': 'Alert.71696387',
        'Old_Reputation - GTI_File': 'Alert.21364739',
        'Old_Reputation - TIE_Cert': 'Alert.88473603',
        'Old_Reputation - TIE_File': 'Alert.38141955',
        'Old_Value': 'Alert.4259884',
        'Operating_System': 'Alert.65579',
        'Organizational_Unit': 'Alert.65605',
        'PCAP_Name': 'Alert.4259881',
        'PID': 'Alert.262152',
        'Parent_File_Hash': 'Alert.262172',
        'Policy_ID': 'Alert.262167',
        'Policy_Name': 'Alert.65544',
        'Priority': 'Alert.4456460',
        'Privileged_User': 'Alert.65578',
        'Privileges': 'Alert.4259879',
        'Process_Name': 'Alert.4259870',
        'Protocol': 'Alert.Protocol',
        'Query_Response': 'Alert.BIN(19)',
        'Queue_ID': 'Alert.196609',
        'RTMP_Application': 'Alert.4259858',
        'Reason': 'Alert.65597',
        'Recipient_ID': 'Alert.65549',
        'Referer': 'Alert.4259851',
        'Registry - Key': 'Alert.21364738',
        'Registry - Value': 'Alert.38141954',
        'Registry_Key': 'Alert.65588',
        'Registry_Value': 'Alert.65589',
        'RemCaseID': 'Alert.RemCaseID',
        'RemOpenTicketTime': 'Alert.RemOpenTicketTime',
        'Reputation': 'Alert.262164',
        'Reputation_Name': 'Alert.65610',
        'Reputation_Score': 'Alert.262171',
        'Reputation_Server_IP': 'Alert.262177',
        'Request_Type': 'Alert.65546',
        'Response_Code': 'Alert.BIN(33)',
        'Response_Time': 'Alert.262145',
        'Return_Code': 'Alert.BIN(34)',
        'Reviewed': 'Alert.Reviewed',
        'Rule.ID': 'Rule.ID',
        'Rule.NormID': 'Rule.NormID',
        'Rule.msg': 'Rule.msg',
        'Rule_NDSNormSigID.msg': 'Rule_NDSNormSigID.msg',
        'Rule_Name': 'Alert.65616',
        'SHA1': 'Alert.65619',
        'SHA256': 'Alert.65630',
        'SNMP_Error_Code': 'Alert.BIN(24)',
        'SNMP_Item': 'Alert.4259868',
        'SNMP_Item_Type': 'Alert.BIN(22)',
        'SNMP_Operation': 'Alert.BIN(21)',
        'SNMP_Version': 'Alert.BIN(23)',
        'SQL_Command': 'Alert.65593',
        'SQL_Statement': 'Alert.4259874',
        'SWF_URL': 'Alert.4259856',
        'Search_Query': 'Alert.4259880',
        'Security_ID': 'Alert.65617',
        'Sensor_Name': 'Alert.BIN(31)',
        'Sensor_Type': 'Alert.BIN(32)',
        'Sensor_UUID': 'Alert.4259869',
        'Sequence': 'Alert.Sequence',
        'Server_ID': 'Alert.262166',
        'Service_Name': 'Alert.65609',
        'SessionID': 'Alert.SessionID',
        'Session_Status': 'Alert.65585',
        'Severity': 'Alert.Severity',
        'Share_Name': 'Alert.65629',
        'SigID': 'Alert.SigID',
        'Signature_Name': 'Alert.65537',
        'Source_Context': 'Alert.4259871',
        'Source_Logon_ID': 'Alert.65583',
        'Source_Network': 'Alert.65572',
        'Source_UserID': 'Alert.65566',
        'Source_Zone': 'Alert.65541',
        'Spam_Score': 'Alert.262157',
        'SrcIP': 'Alert.SrcIP',
        'SrcMac': 'Alert.SrcMac',
        'SrcPort': 'Alert.SrcPort',
        'Start_Page': 'Alert.4456450',
        'Status': 'Alert.65611',
        'Step_Count': 'Alert.65563',
        'Step_Name': 'Alert.65564',
        'Sub_Status': 'Alert.65612',
        'Subcategory': 'Alert.65627',
        'Subject': 'Alert.4259848',
        'TC_URL': 'Alert.4259857',
        'Table_Name': 'Alert.65554',
        'Target_Class': 'Alert.65543',
        'Target_Context': 'Alert.4259872',
        'Target_Process_Name': 'Alert.4259878',
        'ThirdPartyType.Name': 'ThirdPartyType.Name',
        'Threat_Category': 'Alert.65595',
        'Threat_Handled': 'Alert.65596',
        'Threat_Name': 'Alert.65538',
        'To': 'Alert.4259845',
        'To_Address': 'Alert.4259876',
        'Trusted': 'Alert.Trusted',
        'URL': 'Alert.4259841',
        'URL_Category': 'Alert.65586',
        'UUID': 'Alert.262163',
        'UserFld10Cat': 'Alert.UserFld10Cat',
        'UserFld21Cat': 'Alert.UserFld21Cat',
        'UserFld22Cat': 'Alert.UserFld22Cat',
        'UserFld23Cat': 'Alert.UserFld23Cat',
        'UserFld24Cat': 'Alert.UserFld24Cat',
        'UserFld25Cat': 'Alert.UserFld25Cat',
        'UserFld26Cat': 'Alert.UserFld26Cat',
        'UserFld27Cat': 'Alert.UserFld27Cat',
        'UserFld8Cat': 'Alert.UserFld8Cat',
        'UserFld9Cat': 'Alert.UserFld9Cat',
        'UserIDDst': 'Alert.BIN(6)',
        'UserIDDstCat': 'Alert.UserIDDstCat',
        'UserIDSrc': 'Alert.BIN(7)',
        'UserIDSrcCat': 'Alert.UserIDSrcCat',
        'User_Agent': 'Alert.4259849',
        'User_Nickname': 'Alert.BIN(14)',
        'Users.Name': 'Users.Name',
        'VLan': 'Alert.VLan',
        'VPN_Feature_Name': 'Alert.65623',
        'Version': 'Alert.4259859',
        'Victim_IP': 'Alert.262174',
        'Virtual_Machine_ID': 'Alert.65601',
        'Virtual_Machine_Name': 'Alert.65600',
        'Volume_ID': 'Alert.65565',
        'Vulnerability_References': 'Alert.4259882',
        'Web_Domain': 'Alert.65613',
        'WriteTime': 'Alert.WriteTime',
        'ZoneDst': 'Alert.ZoneDst',
        'ZoneSrc': 'Alert.ZoneSrc',
        'Zone_ZoneDst.Name': 'Zone_ZoneDst.Name',
        'Zone_ZoneSrc.Name': 'Zone_ZoneSrc.Name'}
    """
    Best effort SIEM fields mapping
    Todo : Reverse mapping when creating object
    """
    def __getitem__(self, key):
        """
        Best effort to match or autocomplete the field name.
        """
        try :
            val = collections.UserDict.__getitem__(self, key)
            # log.debug('Returning __getitem__(self, {}) -> {}'.format(key, val))
            return val

        except (AttributeError, KeyError) : 
            if key in self.SIEM_FIELDS_MAP :
                try :
                    val = collections.UserDict.__getitem__(self, self.SIEM_FIELDS_MAP[key])
                    # log.debug('Returning __getitem__(self, SIEM_FIELDS_MAP[{}]) -> {}'.format(key, val))
                    return val
                except (AttributeError, KeyError) : 
                    # log.debug('Errored __getitem__(self, SIEM_FIELDS_MAP[{}])'.format(key))
                    pass

            for table in self.FIELDS_TABLES :
                try :
                    val = collections.UserDict.__getitem__(self, table+'.'+key)
                    # log.debug('Returning __getitem__(self, {}.{}) -> {}'.format(table, key, val))
                    return val
                except (AttributeError, KeyError) : 
                    # log.debug('Errored __getitem__(self, {}.{})'.format(table, key))
                    pass

            log.error('KeyError : {}. The SIEM dict keys are not always the same are the requested fields. Check `.keys()`.'.format(key))
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
        
    def data_from_id(self, id, use_query=False, extra_fields=[]):
        """
        Load event's data.  

        Arguments:   

        - `id` : The event ID. (i.e. : `144128388087414784|747122896`)  
        - `use_query` : Uses the query module to retreive common event data. Only works with SIEM v 11.2.x.  
        - `extra_fields` : Only when `use_query=True`. Additionnal event fields to load in the query.  
        """
        
        if use_query == True :

            e = EventManager(
                time_range='CUSTOM',
                start_time=datetime.now()-timedelta(days=365),
                end_time=datetime.now()+timedelta(days=1),
                filters=[('IPSIDAlertID',id)],
                fields=extra_fields,
                limit=2)
                
            e.load_data()

            if len(e) == 1 :
                return e[0]
            else :
                raise NitroError('Could not load event : '+str(id)+' from query :'+str(e.__dict__)+'. Try with use_query=False.')

        elif use_query == False :
            return self.nitro.request('get_alert_data', id=id)

    def refresh(self): 
        """Re-load event's data"""
        if 'Alert.IPSIDAlertID' in self.data.keys() :
            self.data.update(self.data_from_id(self.data['Alert.IPSIDAlertID'], 
                use_query=True, extra_fields=self.data.keys()))
        else :
            id = '|'.join([str(self.data['ipsId']['id']), str(self.data['alertId'])])
            self.data.update(self.data_from_id(id))
   
class _QueryFilter(collections.UserDict):
    """Base class for all SIEM query objects in order to dump the filter as dict.
    """

class GroupFilter(_QueryFilter):
    """
        Based on EsmFilterGroup. See SIEM api doc.
        Used to dump groups of filters in the right format.

        Arguments :  

        - `filters` : a list of filters, it can be `msiempy.event.FieldFilter` or `msiempy.event.GroupFilter`  
        - `logic` : 'AND' or 'OR'  
    """

    def __init__(self, filters, logic='AND') :
        super().__init__()
        
        #Declaring attributes
        self.data={
            "type": "EsmFilterGroup",
            "filters": [dict(f) for f in filters],
            "logic":logic
            }
        
class FieldFilter(_QueryFilter):
    """
    Based on EsmFieldFilter. See SIEM api doc.
    Used to dump a filter in the right format.

    Arguments:

        - `name` : field name as string. Field name property. Example : `SrcIP`. See full list here: https://github.com/mfesiem/msiempy/blob/master/static/all_filters.json
        - `values` : list of values the field is going to be tested againts with the specified orperator.  
        - `orperator` : `IN`,
        `NOT_IN`,
        `GREATER_THAN`,
        `LESS_THAN`,
        `GREATER_OR_EQUALS_THAN`,
        `LESS_OR_EQUALS_THAN`,
        `NUMERIC_EQUALS`,
        `NUMERIC_NOT_EQUALS`,
        `DOES_NOT_EQUAL`,
        `EQUALS`,
        `CONTAINS`,
        `DOES_NOT_CONTAIN`,
        `REGEX`.  
    """

    def __init__(self, name, values, operator='IN') :
        super().__init__()
        #Declaring attributes
        self._operator=str()
        self._values=list()
        self.name = name
        self.operator = operator
        self.values = values

        self.data={
            "type": "EsmFieldFilter",
            "field": {"name": self.name},
            "operator": self.operator,
            "values": self.values
            }

    
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
    """List of possibles operators"""

    POSSIBLE_VALUE_TYPES=[
            {'type':'EsmWatchlistValue',    'key':'watchlist'},
            {'type':'EsmVariableValue',     'key':'variable'},
            {'type':'EsmBasicValue',        'key':'value'},
            {'type':'EsmCompoundValue',     'key':'values'}]
    """
    List of possible value type. See `msiempy.event.FieldFilter.add_value`.
    """
   
    @property
    def operator(self):
        """Field operator.  
        Setter check the value against the list of possible operators and trow `AttributeError` if not present.
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
        """List of values of the filter.  
        Setter iterate trough the list and call : 

        - `msiempy.FilteredQueryList.add_value()` if value is a `dict`
        - `msiempy.FilteredQueryList.add_basic_value()` if value type is `int`, `float` or `str`.

        Values will always be added to the filter. To remove values, handle directly the `_values` property.

        Example :  
            `filter = FieldFilter(name='DstIP',values=['10.1.13.0/24', {'type':'EsmWatchlistValue', 'watchlist':42}], operator='IN')`
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
        
    def add_value(self, type=None, **kwargs):
        """
        Add a new value to the field filter.  
        
        Arguments (`**kwargs` depends on the value `type`):  

        - `type` (`str`) : Type of the value    
        - `value` (`str`) : If `type` is `EsmBasicValue`  
        - `watchlist` (`int`) : if `type` is `EsmWatchlistValue`    
        - `variable` (`int`) if `type` is `EsmVariableValue`    
        - `values` (`list`) if `type` is `EsmCompoundValue`  
        
        Raises : `KeyError` or `AttributeError` if you don't respect the correct type/key/value combo.  
        Note : Filtering query with other type of filter than `EsmBasicValue` is not tested.
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
            if type_template != None :
                if type_template['key'] in kwargs :
                    
                    # Adds a new value to a fields filter
                    # Filtering query with other type of filter than 'EsmBasicValue' is not tested.
                    value = kwargs[type_template['key']]
                    if type == 'EsmBasicValue' :
                        value=str(value)
                        #log.debug('Adding a basic value to filter ('+self.text+') : '+value)
                    self._values.append({'type':type, type_template['key']:value})
                    #log.debug('The value was appended to the list: '+str(self))
                    
                #Error throwing
                else: raise KeyError ('The valid key value argument is not present')
            else: raise KeyError ('Impossible filter')
        except KeyError as err:
            raise AttributeError("You must provide a valid named Arguments containing the type and values for this filter. The type/keys must be in "+str(self.POSSIBLE_VALUE_TYPES)+"Can't be type="+str(type)+' '+str(kwargs)+". Additionnal indicator :"+str(err) )

    def add_basic_value(self, value):
        """
        Wrapper arround `add_value` method to simply add a `EsmBasicValue`.
        """
        self.add_value(type='EsmBasicValue', value=value)
