# -*- coding: utf-8 -*-
""" 
    msiem constants
"""
POSSIBLE_FIELD_TYPES = [ 'BOOLEAN',
            'STRING',
            'CUSTOM',
            'INT2',
            'INT4',
            'INT8',
            'INT32',
            'INT64',
            'UINT8',
            'UINT16',
            'UINT32',
            'UINT64',
            'IPV4',
            'FLOAT',
            'SIGID',
            'SSTRING',
            'IPTYPE',
            'IP',
            'GUID',
            'MAC_ADDRESS',
            'LONG_CUSTOM',
            'HSTRING',
            'STRLIT',
            'AGG',
            'TIME4',
            'TIME8']
            
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

DEFAULT_TIME_RANGE="LAST_30_MINUTES"
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

POSSIBLE_ALARM_STATUS=[
        ('acknowledged', 'ack',),
        ('unacknowledged', 'unack',),
        ('', None, 'all', 'both')
    ]

POSSBILE_ROW_ORDER=[
        'ASCENDING',
        'DESCENDING'
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

ALARM_FILTER_FIELDS = [('id',),
('summary','sum'),
('assignee','user'),
('severity','sever'),
('triggeredDate','trigdate'),
('acknowledgedDate','ackdate'),
('acknowledgedUsername','ackuser'),
('alarmName','name'),
]

ALARM_EVENT_FILTER_FIELDS=[("eventId",),
#"severity", duplicated in ALARM_FILTER_FIELD
#("severity", "eventseverity",),
("ruleMessage",'msg','rulemsg'),
("eventCount",'count'),
("sourceIp",'srcip'),
("destIp",'dstip'),
("protocol",'prot'),
("lastTime",'date'),
("eventSubType",'subtype')]

ALARM_DEFAULT_FIELDS=['triggeredDate','alarmName','status','sourceIp','destIp','ruleMessage']

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

