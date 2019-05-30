# -*- coding: utf-8 -*-
"""
    msiem.params
    ~~~~~~~~~~~~~

    This module imports a dict into the msiem core class to provide
    a central place to aggregate methods and parameters. The params
    are stored as docstrings to support string replacement.

    Args:
        method (str): Dict key associated with desired function
        Use normal dict access, ['method'], or .pop('method')

    Returns:
        tuple: (string, string)

        The first string is the method name that is actually used as
        the URI or passed to the ESM. The second string is the params
        required for that method. Some params require variables be
        interpolated as documented in the Attributes.

    Example:
        method, params = params['login'].format(username, password)

    Attributes:
        login: Function to login
            vars:
                username
                password
            callback vars:
                Cookie
                X-Xsrf-Token

        devtree: Get top level device tree string

        client_grp: Get clients for a specific group
            vars:
                id
            callback vars:
                ftoken

        results: Get results from earlier call
            vars:
                ftoken

"""

PARAMS = {
    'login': ("login",
              """{'username': '%(username)s',
                 'password' : '%(password)s',
                 'locale': 'en_US',
                 'os': 'Win32'}
                 """),

    'get_devtree': ("GRP_GETVIRTUALGROUPIPSLISTDATA",
                    """{'ITEMS': '#{DC1 + DC2}',
                        'DID': '1',
                        'HD': 'F',
                        'NS': '0'}
                    """),

    'get_zones_devtree': ("GRP_GETVIRTUALGROUPIPSLISTDATA",
                    """{'ITEMS': '#{DC1 + DC2}',
                        'DID': '3',
                        'HD': 'F',
                        'NS': '0'}
                    """),

    'req_client_str': ("DS_GETDSCLIENTLIST",
                          """{'DSID': '%(_ds_id)s',
                              'SEARCH': ''}
                          """),

    'get_rfile': ("MISC_READFILE",
                 """{'FNAME': '%(_ftoken)s',
                 'SPOS': '0',
                 'NBYTES': '0'}
                 """),

    'get_wfile': ("MISC_WRITEFILE",
                 """{'DATA1': '%(_ds_id)s',
                 """),

                 
                 
    'map_dtree': ("map_dtree",
                  """{'dev_type': '%(dev_type)s',
                  'name': '%(ds_name)s',
                  'ds_id': '%(ds_id)s',
                  'enabled': '%(enabled)s',
                  'ds_ip': '%(ds_ip)s',
                  'hostname' : '%(hostname)s',
                  'typeID': '%(type_id)s',
                  'vendor': '',
                  'model': '',
                  'tz_id': '',
                  'date_order': '',
                  'port': '',
                  'syslog_tls': '',
                  'client_groups': '%(client_groups)s'
                  }
                  """),
                 
    'add_ds': ("dsAddDataSource", 
                """{'datasource': {
                        'parentId': {'id': '%(parent_id)s'},
                        'name': '%(name)s',
                        'id': {'id': '%(ds_id)s'},
                        'typeId': {'id': '%(type_id)s'},
                        'childEnabled': '%(child_enabled)s',
                        'childCount': '%(child_count)s',
                        'childType': '%(child_type)s',
                        'ipAddress': '%(ds_ip)s',
                        'zoneId': '%(zone_id)s',
                        'url': '%(url)s',
                        'enabled': '%(enabled)s',
                        'idmId': '%(idm_id)s',
                        'parameters': %(parameters)s
                    }}"""),

    'add_client': ("DS_ADDDSCLIENT", 
                     """{'PID': '%(parent_id)s',
                     'NAME': '%(name)s',
                     'ENABLED': '%(enabled)s',
                     'IP': '%(ds_ip)s',
                     'HOST': '%(hostname)s',
                     'TYPE': '%(type_id)s',
                     'TZID': '%(tz_id)s',
                     'DORDER': '%(dorder)s',
                     'MASKFLAG': '%(maskflag)s',
                     'PORT': '%(port)s',
                     'USETLS': '%(syslog_tls)s'
                    }"""),
                    
    'get_recs': ("devGetDeviceList?filterByRights=false",
                     """{'types': ['RECEIVER']}
                     """),

    'get_dstypes': ("dsGetDataSourceTypes",
                     """{'receiverId': {'id': '%(rec_id)s'}
                        }
                     """),
                     
    'del_ds': ("dsDeleteDataSource",
                """{'receiverId': {'id': '%(parent_id)s'},
                    'datasourceId': {'id': '%(ds_id)s'}}
                 """),
                 
    'del_client': ("DS_DELETEDSCLIENTS",
                    """{}
                    """
                    ),
                    
    'ds_last_times': ("QRY%5FGETDEVICELASTALERTTIME",
                      """{}
                      """),
                      
    'zonetree': ("zoneGetZoneTree",
                      """{}
                      """),
                      
    'ds_by_type': ("QRY_GETDEVICECOUNTBYTYPE",
                      """{}
                      """),

   '_dev_types':  ("dev_type_map",
                    """{'1': 'zone',
                        '2': 'ERC',
                        '3': 'datasource',
                        '4': 'Database Event Monitor (DBM)',
                        '5': 'DBM Database',
                        '7': 'Policy Auditor',
                        '10': 'Application Data Monitor (ADM)',
                        '12': 'ELM',
                        '14': 'Local ESM',
                        '15': 'Advanced Correlation Engine (ACE)',
                        '16': 'Asset datasource',
                        '17': 'Score-based Correlation',
                        '19': 'McAfee ePolicy Orchestrator (ePO)',
                        '20': 'EPO',
                        '21': 'McAfee Network Security Manager (NSM)',
                        '22': 'McAfee Network Security Platform (NSP)',
                        '23': 'NSP Port',
                        '24': 'McAfee Vulnerability Manager (MVM)',
                        '25': 'Enterprise Log Search (ELS)',
                        '254': 'client_group',
                        '256': 'client'}
                    """),
                    
    'ds_details': ("dsGetDataSourceDetail",
                    """{'datasourceId': 
                        {'id': '%(ds_id)s'}}
                    """),

    'get_alarms_custom_time': ("""alarmGetTriggeredAlarms?triggeredTimeRange=%(time_range)s&customStart=%(start_time)s&customEnd=%(end_time)s&status=%(status)s&pageSize=%(page_size)s&pageNumber=%(page_number)s""",
                   None),

    'get_alarms': ("""alarmGetTriggeredAlarms?triggeredTimeRange=%(time_range)s&status=%(status)s&pageSize=%(page_size)s&pageNumber=%(page_number)s""", None),

    'get_alarm_details': ("""notifyGetTriggeredNotification""", """{"id":%(id)s}"""),

    'ack_alarms': ("""alarmAcknowledgeTriggeredAlarm""", """{"triggeredIds":%(ids)s}"""),

    'unack_alarms': ("""alarmUnacknowledgeTriggeredAlarm""", """{"triggeredIds":%(ids)s}"""),

    'delete_alarms': ("""alarmDeleteTriggeredAlarm""", """{"triggeredIds":%(ids)s}"""),
    
    'get_possible_filters' : ( """qryGetFilterFields""", None ),

    'get_possible_fields' : ( """qryGetSelectFields?type=%(type)s&groupType=%(groupType)s""", None ),

    'get_esm_time' : ( """essmgtGetESSTime""",None),

    'logout' : ( """userLogout""", None ),

    'get_user_locale' : ( """getUserLocale""", None ),

    'event_query_custom_time' : ("""qryExecuteDetail?type=EVENT&reverse=false""", """
        {"config": {
            "timeRange": "%(time_range)s",
            "customStart": "%(start_time)s",
            "customEnd": "%(end_time)s",
            "fields": %(fields)s,
            "filters": %(filters)s,
            "limit": %(limit)s,
            "offset": %(offset)s
            }
        }"""),

    'event_query' : ("""qryExecuteDetail?type=EVENT&reverse=false""", """
        {"config": {
            "timeRange": "%(time_range)s",
            "fields": %(fields)s,
            "filters": %(filters)s,
            "limit": %(limit)s,
            "offset": %(offset)s
            }
        }"""),

    'query_status' : ("""qryGetStatus""", """{"resultID": %(resultID)s}"""),

    'query_result' : ("""qryGetResults?startPos=%(startPos)s&numRows=%(numRows)s&reverse=false""", """{"resultID": %(resultID)s}"""),
    
    'time_zones' : ("""userGetTimeZones""", None)
    

}

