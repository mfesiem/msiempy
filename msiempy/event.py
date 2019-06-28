import time
import logging
log = logging.getLogger('msiempy')

from .base import Item
from .query import QueryManager, FieldFilter, GroupFilter, QueryFilter
from .error import NitroError
from .utils import timerange_gettimes, parse_query_result, format_fields_for_query

class EventManager(QueryManager):
    """
    EventManager class.
    Interface to query and manage events.
    Inherits from QueryManager.
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
           Params
           ======
           
            fields : list of strings representing all fields you want to apprear in the Events records.
                Get the list of possible fields by calling EventManager.get_possible_fields() method.
                Some defaults fields will always be present unless removed, see (1).
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
            *args, **kwargs : Parameters passed to `msiempy.base.QueryManager.__init__()`
           
            
            Examples
            ========
            
            (1) To delete a default field
            ```
                >>>em=EventManager()
                >>>del em.fields['SrcIP']
            ```
            
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

        #TODO : find a solution not to use this stinky tric
        #callign super().filters=filters #https://bugs.python.org/issue14965
        super(self.__class__, self.__class__).filters.__set__(self, filters)

        #Type cast all items in the list "data" to events type objects
        self.type_cast_items_to_events()

    def type_cast_items_to_events(self):
        """Type cast all items in the list "data" to events type objects"""
        
        events = []
        for item in self.data:
            event = Event(item)
            events.append(event)

        self.data = events

    @property
    def order(self):
        """
        Return a list of orders representing the what the SIEM is expecting as the 'order'
        """
        return(self._order)

    @order.setter
    def order(self, order):
        """
        The order must be tuple (direction, field).
        Use _order to set with SIEM format.
        """
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
        Generates the json SIEM formatted filters for the query by calling reccursive getter : config_dict.
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

    def load_data(self):
        """
        Specialized EventManager load_data method.
        Use super load_data implementation.
        You could decide not to use the splitting feature by 
            calling directly _load_data() 
        """
        return EventManager(alist=super().load_data())

    def _wait_for(self, resultID, sleep_time=0.35):
        """
        Internal method called by _load_data
        Wait and sleep - for `sleep_time` duration in seconds -
            until the query is completed
        
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
        events=parse_query_result(result['columns'], result['rows'])
        return events
          
class Event(Item):
    """
    Event.
    You can see all the requested fields and have some 
        interaction - note only - with the events
    """
    """
    Possible event fields that can be used in filters :
        AppID
        CommandID
        DomainID
        HostID
        ObjectID
        UserIDDst
        UserIDSrc
        URL
        Database_Name
        Message_Text
        Response_Time
        Application_Protocol
        Object_Type
        Filename
        From
        To
        Cc
        Bcc
        Subject
        Method
        User_Agent
        Cookie
        Referer
        File_Operation
        File_Operation_Succeeded
        Destination_Filename
        User_Nickname
        Contact_Name
        Contact_Nickname
        Client_Version
        Job_Name
        Language
        SWF_URL
        TC_URL
        RTMP_Application
        Version
        Local_User_Name
        NAT_Details
        Network_Layer
        Transport_Layer
        Session_Layer
        Application_Layer
        HTTP_Layer
        HTTP_Req_URL
        HTTP_Req_Cookie
        HTTP_Req_Referer
        HTTP_Req_Host
        HTTP_Req_Method
        HTTP_User_Agent
        DNS_Name
        DNS_Type
        DNS_Class
        Query_Response
        Authoritative_Answer
        SNMP_Operation
        SNMP_Item_Type
        SNMP_Version
        SNMP_Error_Code
        NTP_Client_Mode
        NTP_Server_Mode
        NTP_Request
        NTP_Opcode
        SNMP_Item
        Interface
        Direction
        Sensor_Name
        Sensor_UUID
        Sensor_Type
        Signature_Name
        Threat_Name
        Destination_Hostname
        Category
        Process_Name
        Grid_Master_IP
        Response_Code
        Device_Port
        Device_IP
        PID
        Target_Context
        Source_Context
        Target_Class
        Policy_Name
        Destination_Zone
        Source_Zone
        Queue_ID
        Delivery_ID
        Recipient_ID
        Spam_Score
        Mail_ID
        To_Address
        From_Address
        Message_ID
        Request_Type
        SQL_Statement
        External_EventID
        Event_Class
        Description
        Access_Privileges
        Rule_Name
        App_Layer_Protocol
        Group_Name
        Vulnerability_References
        Web_Domain
        Sub_Status
        Status
        Reputation_Name
        PCAP_Name
        Search_Query
        Service_Name
        External_Device_Name
        External_Device_ID
        External_Device_Type
        Organizational_Unit
        Privileges
        Interface_Dest
        Datacenter_Name
        Datacenter_ID
        Virtual_Machine_ID
        Virtual_Machine_Name
        Detection_Method
        Target_Process_Name
        Analyzer_DAT_Version
        Forwarding_Status
        Reason
        Threat_Handled
        Threat_Category
        Device_Action
        Database_GUID
        SQL_Command
        Destination_Directory
        Directory
        Mailbox
        Handheld_ID
        Policy_ID
        Server_ID
        Registry_Value
        Registry_Key
        Caller_Process
        DAT_Version
        Reputation
        URL_Category
        Session_Status
        Destination_Logon_ID
        Source_Logon_ID
        UUID
        External_SessionID
        Management_Server
        Logon_Type
        Operating_System
        File_Path
        Agent_GUID
        Instance_GUID
        Privileged_User
        Facility
        Area
        External_Hostname
        Incoming_ID
        Handle_ID
        Destination_Network
        Source_Network
        Malware_Insp_Result
        Malware_Insp_Action
        Return_Code
        Database_ID
        File_Hash
        Mainframe_Job_Name
        External_SubEventID
        Destination_UserID
        Source_UserID
        Volume_ID
        Step_Name
        Step_Count
        LPAR_DB2_Subsystem
        Logical_Unit_Name
        Job_Type
        FTP_Command
        File_Type
        DB2_Plan_Name
        Catalog_Name
        Access_Resource
        Table_Name
        External_DB2_Server
        External_Application
        Creator_Name
        Authentication_Type
        New_Value
        Old_Value
        Security_ID
        VPN_Feature_Name
        Access_Mask
        Attribute_Type
        Engine_List
        Device_URL
        Attacker_IP
        Victim_IP
        Incident_ID
        File_ID
        Reputation_Score
        SHA1
        Parent_File_Hash
        Object_GUID
        Reputation_Server_IP
        Hash_Type
        Hash
        Subcategory
        Wireless_SSID
        DNS_Server_IP
        CnC_Host
        Share_Name
        Device_Confidence
        Rule_Number
        SHA256
        AppID
        CommandID
        DSIDSigID
        Action
        ASNGeoDst
        DSID
        ZoneDst
        SigID
        GUIDSrc
        NDDevIDSrc
        ID
        Protocol
        NormID
        ZoneSrc
        FirstTime
        SrcPort
        AvgSeverity
        DstPort
        SrcIP
        GUIDDst
        DstIP
        NDDevIDDst
        SrcMac
        SessionID
        ASNGeoSrc
        DstMac
        LastTime 
    """
    
    """
        
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

    """Relatively common event fields that could be useful to have.
    """
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
            Not working properly i think
            #TODO try with collections.UserDict.__getitem__(self, key)
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
        """
        Desctructive action.
        Replace the notes by an empty string. 
        """
        NotImplementedError()

    def add_note(self, note):
        """
        Add a new note in the note field.
        """
        #We've tried all of these parameters and none of them works...
        print("We've tried all of these parameters and none of them works...")
        print("Alert.DSIDSigID: " + self.data["Alert.DSIDSigID"])
        self.nitro.request("add_note_to_event", id=self.data["Alert.DSIDSigID"], note=note)
        print("Alert.IPSID: " + self.data["Alert.IPSID"])
        self.nitro.request("add_note_to_event", id=self.data["Alert.IPSID"], note=note)
        print("Alert.AlertID: " + self.data["Alert.AlertID"])
        self.nitro.request("add_note_to_event", id=self.data["Alert.AlertID"], note=note)
        print("Rule.NormID: " + self.data["Rule.NormID"])
        self.nitro.request("add_note_to_event", id=self.data["Rule.NormID"], note=note)
        
    