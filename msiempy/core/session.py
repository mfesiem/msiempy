# -*- coding: utf-8 -*-
"""
HTTP level interface to the ESM API.  
"""
import logging
import requests
import json
import ast
import re
import urllib.parse
import inspect
import time
import urllib3

from .utils import tob64
from .config import NitroConfig

log = logging.getLogger('msiempy')

__pdoc__ = {} # Init pdoc to document dynamically

PARAMS = {
    "login": ("login",
            """{"username": "%(username)s",
                "password" : "%(password)s",
                "locale": "en_US",
                "os": "Win32"}
                """),

    "get_devtree": ("GRP_GETVIRTUALGROUPIPSLISTDATA",
                    """{"ITEMS": "#{DC1 + DC2}",
                        "DID": "1",
                        "HD": "F",
                        "NS": "0"}
                    """),

    "get_zones_devtree": ("GRP_GETVIRTUALGROUPIPSLISTDATA",
                    """{"ITEMS": "#{DC1 + DC2}",
                        "DID": "3",
                        "HD": "F",
                        "NS": "0"}
                    """),

    "req_client_str": ("DS_GETDSCLIENTLIST",
                        """{"DSID": "%(ds_id)s",
                            "SEARCH": ""}
                        """),

    "get_rfile": ("MISC_READFILE",
                """{"FNAME": "%(ftoken)s",
                "SPOS": "0",
                "NBYTES": "0"}
                """),

    "del_rfile": ("ESSMGT_DELETEFILE",
                """{"FN": "%(ftoken)s"}"""),

    "get_rfile2": ("MISC_READFILE",
                """{"FNAME": "%(ftoken)s",
                "SPOS": "%(pos)s",
                "NBYTES": "%(nbytes)s"}
                """),

    "get_wfile": ("MISC_WRITEFILE",
                """{"DATA1": "%(ds_id)s",
                        "PATH": "21",
                        "ND": "1"} """),
    
    "get_rule_history": ("PLCY_GETRULECHANGEINFO", 
                        """{"SHOW": "F"}"""),

    "map_dtree": ("map_dtree",
                """{"dev_type": "%(dev_type)s",
                "name": "%(ds_name)s",
                "ds_id": "%(ds_id)s",
                "enabled": "%(enabled)s",
                "ds_ip": "%(ds_ip)s",
                "hostname" : "%(hostname)s",
                "typeID": "%(type_id)s",
                "vendor": "",
                "model": "",
                "tz_id": "",
                "date_order": "",
                "port": "",
                "syslog_tls": "",
                "client_groups": "%(client_groups)s"
                }
                """),

    "add_ds_11_1_3": ("dsAddDataSource", 
                """{"datasource": {
                        "parentId": {"id": "%(parent_id)s"},
                        "name": "%(name)s",
                        "ipAddress": "%(ds_ip)s",
                        "typeId": {"id": "%(type_id)s"},
                        "zoneId": "%(zone_id)s",
                        "enabled": "%(enabled)s",
                        "url": "%(url)s",
                        "id": {"id": "%(ds_id)s"},
                        "childEnabled": "%(child_enabled)s",
                        "childCount": "%(child_count)s",
                        "childType": "%(child_type)s",
                        "idmId": "%(idm_id)s",
                        "parameters": %(parameters)s
                    }}"""),

    "add_ds_11_2_1": ("dsAddDataSources", 
                    """{"receiverId": "%(parent_id)s",
                        "datasources": [{
                            "name": "%(name)s",
                            "ipAddress": "%(ds_ip)s",
                            "typeId": {"id": "%(type_id)s"},
                            "zoneId": "%(zone_id)s",
                            "enabled": "%(enabled)s",
                            "url": "%(url)s",
                            "parameters": %(parameters)s
                            }]}"""),

    "add_client1": ("DS_ADDDSCLIENT", 
                    """{"PID": "%(parent_id)s",
                    "NAME": "%(name)s",
                    "ENABLED": "%(enabled)s",
                    "IP": "%(ds_ip)s",
                    "HOST": "%(hostname)s",
                    "TYPE": "%(type_id)s",
                    "TZID": "%(tz_id)s",
                    "DORDER": "%(dorder)s",
                    "MASKFLAG": "%(maskflag)s",
                    "PORT": "%(port)s",
                    "USETLS": "%(require_tls)s"
                    }"""),
                    
    "get_recs": ("devGetDeviceList?filterByRights=false",
                    """{"types": ["RECEIVER"]}
                    """),

    "get_dstypes": ("dsGetDataSourceTypes",
                    """{"receiverId": {"id": "%(rec_id)s"}
                        }
                    """),
                    
    "del_ds1": ("dsDeleteDataSource",
                """{"receiverId": {"id": "%(parent_id)s"},
                    "datasourceId": {"id": "%(ds_id)s"}}
                """),

    "del_ds2": ("dsDeleteDataSources",
                """{"receiverId": {"value": "%(parent_id)s"},
                    "datasourceIds": [{"value": "%(ds_id)s"}]}
                """),

    "del_client": ("DS_DELETEDSCLIENTS", 
                    """{"DID": "%(parent_id)s",
                            "FTOKEN": "%(ftoken)s"}"""
                    ),

    "get_job_status": ("MISC_JOBSTATUS",
                        """{"JID": "%(job_id)s"}"""),

    "ds_last_times": ("QRY_GETDEVICELASTALERTTIME","""{}"""),
                    
    "zonetree": ("zoneGetZoneTree",None),
                    
    "ds_by_type": ("QRY_GETDEVICECOUNTBYTYPE",None),

    "_dev_types":  ("dev_type_map",
                        """{"1": "zone",
                            "2": "ERC",
                            "3": "datasource",
                            "4": "Database Event Monitor (DBM)",
                            "5": "DBM Database",
                            "7": "Policy Auditor",
                            "10": "Application Data Monitor (ADM)",
                            "12": "ELM",
                            "14": "Local ESM",
                            "15": "Advanced Correlation Engine (ACE)",
                            "16": "Asset datasource",
                            "17": "Score-based Correlation",
                            "19": "McAfee ePolicy Orchestrator (ePO)",
                            "20": "EPO",
                            "21": "McAfee Network Security Manager (NSM)",
                            "22": "McAfee Network Security Platform (NSP)",
                            "23": "NSP Port",
                            "24": "McAfee Vulnerability Manager (MVM)",
                            "25": "Enterprise Log Search (ELS)",
                            "254": "client_group",
                            "256": "client"}
                        """),
                        
        "ds_details1": ("dsGetDataSourceDetail",
                        """{"datasourceId": 
                            {"id": "%(ds_id)s"}}
                        """),

        "ds_details2": ("dsGetDataSourceDetail",
                        """{"datasourceId": {"value": "%(ds_id)s"}}"""),


        "get_alarms_custom_time": ("""alarmGetTriggeredAlarms?triggeredTimeRange=%(time_range)s&customStart=%(start_time)s&customEnd=%(end_time)s&status=%(status)s&pageSize=%(page_size)s&pageNumber=%(page_number)s""",
                    None),

        "get_alarms": ("""alarmGetTriggeredAlarms?triggeredTimeRange=%(time_range)s&status=%(status)s&pageSize=%(page_size)s&pageNumber=%(page_number)s""", None),

        "get_alarm_details_new": ("""notifyGetTriggeredNotificationDetail""", """{"id":%(id)s}"""),

        "get_alarm_details": ("""notifyGetTriggeredNotification""", """{"id":%(id)s}"""),

        "get_alarm_details_int": ("NOTIFY_GETTRIGGEREDNOTIFICATIONDETAIL", 
                                    """{"TID": "%(id)s"}"""),

        "ack_alarms": ("""alarmAcknowledgeTriggeredAlarm""", """{"triggeredIds":[{"value":%(ids)s}]}"""),

        "ack_alarms_11_2_1": ("""alarmAcknowledgeTriggeredAlarm""", """{"triggeredIds":{"alarmIdList":[%(ids)s]}}"""),

        "unack_alarms": ("""alarmUnacknowledgeTriggeredAlarm""", """{"triggeredIds":[{"value":%(ids)s}]}"""),

        "unack_alarms_11_2_1": ("""alarmUnacknowledgeTriggeredAlarm""", """{"triggeredIds":{"alarmIdList":[%(ids)s]}}"""),

        "delete_alarms": ("""alarmDeleteTriggeredAlarm""", """{"triggeredIds":[{"value":%(ids)s}]}"""),
        
        "delete_alarms_11_2_1": ("""alarmDeleteTriggeredAlarm""", """{"triggeredIds":{"alarmIdList":[%(ids)s]}}"""),

        "get_possible_filters" : ( """qryGetFilterFields""", None ),

        "get_possible_fields" : ( """qryGetSelectFields?type=%(type)s&groupType=%(groupType)s""", None ),

        "get_esm_time" : ( """essmgtGetESSTime""",None),

        "get_alerts_now" : ("""IPS_GETALERTSNOW""", """{"IPSID": "%(ds_id)s"}"""),

        "get_flows_now" : ("""IPS_GETALERTSNOW""", """{"IPSID": "%(ds_id)s"}"""),

        "logout" : ( """userLogout""", None ),

        "get_user_locale" : ( """getUserLocale""", None ),

        "event_query_custom_time" : ("""qryExecuteDetail?type=EVENT&reverse=false""", """{
                "config": {
                    "timeRange": "%(time_range)s",
                    "customStart": "%(start_time)s",
                    "customEnd": "%(end_time)s",
                    "fields": %(fields)s,
                    "filters": %(filters)s,
                    "limit": %(limit)s,
                    "offset": %(offset)s,
                    "order": [{"field": {"name": "%(order_field)s"},
                                            "direction": "%(order_direction)s"}]
                    }
                    }"""),

        "event_query" : ("""qryExecuteDetail?type=EVENT&reverse=false""", """{
                "config": {
                    "timeRange":"%(time_range)s",
                    "fields":%(fields)s,
                    "filters":%(filters)s,
                    "limit":%(limit)s,
                    "offset":%(offset)s,
                    "order": [{"field": {"name": "%(order_field)s"},
                                            "direction": "%(order_direction)s"}]
                    }
                    }"""),

        "query_status" : ("""qryGetStatus""", """{"resultID": %(resultID)s}"""),

        "query_result" : ("""qryGetResults?startPos=%(startPos)s&numRows=%(numRows)s&reverse=false""", """{"resultID": %(resultID)s}"""),
        
        "time_zones" : ("""userGetTimeZones""", None),

        "logout" : ("""logout""", None),
        
        "add_note_to_event" : ("""ipsAddAlertNote""", """{
            "id": {"value": "%(id)s"},
            "note": {"note": "%(note)s"}
        }"""),

        "add_note_to_event_int": ("""IPS_ADDALERTNOTE""", """{"AID": "%(id)s",
                                                            "NOTE": "%(note)s"}"""),

        "get_wl_types": ("""sysGetWatchlistFields""", None),
        "get_watchlists_no_filters" : ("""sysGetWatchlists?hidden=%(hidden)s&dynamic=%(dynamic)s&writeOnly=%(writeOnly)s&indexedOnly=%(indexedOnly)s""", 
            None),

        "get_watchlist_details": ("""sysGetWatchlistDetails""","""{"id": %(id)s}"""),

        "add_watchlist": ("""sysAddWatchlist""", """{
            "watchlist": {
                "name": "%(name)s",
                "type": {"name": "%(wl_type)s",
                            "id": 0},
                "customType": {"name": "",
                                "id": 0},
                "dynamic": "False",
                "enabled": "True",
                "search": "",
                "source": 0,
                "updateType": "EVERY_SO_MANY_MINUTES",
                "updateDay": 0,
                "updateMin": 0,
                "ipsid": "0",
                "valueFile": {"fileToken": ""},
                "dbUrl": "",
                "mountPoint": "",    
                "path": "",
                "port": "22",
                "username": "",
                "password": "",
                "query": "",
                "lookup": "",
                "jobTrackerURL": "",
                "jobTrackerPort": "",
                "postArgs": "",
                "ignoreRegex": "",
                "method": 0,
                "matchRegex": "",
                "lineSkip": 0,
                "delimitRegex": "",
                "groups": 1
                            }}"""),
                                                        
        "add_watchlist_values": ("""sysAddWatchlistValues""","""{
            "watchlist": %(watchlist)s,
            "values": %(values)s,
            }"""),

        "get_watchlist_values": ("SYS_GETWATCHLISTDETAILS",
                                        """{"WID": "%(id)s", "LIM": "T"}"""),

        "remove_watchlists": ("""sysRemoveWatchlist""", """{"ids": {"watchlistIdList": ["%(wl_id_list)s"]}}"""),

        "get_alert_data": ("""ipsGetAlertData""", """{"id": {"value":"%(id)s"}}"""),
        
        "get_sys_info"  : ("SYS_GETSYSINFO","""{}"""),
        
        "build_stamp" : ("essmgtGetBuildStamp",None)
} 
__pdoc__['msiempy.core.session.PARAMS'] = '''
SIEM API Methos/Parameters mapping.  
This structure provide a central place to aggregate API methods and parameters.  
The parameters are stored as docstrings to support string replacement.  

Args:  
    - `method` (str): Dict key associated with desired function
    Use normal dict access, `PARAMS["method"]`, or `PARAMS.get("method")`

Returns:  
    - `tuple `: `(string, string)` :  
    The first string is the SIEM API endpoint name.  
    The second string is the JSON formatted parameters required for the enpoint call. 
    The formatted string contains interpolation flags like `%(id)` and will be matched to `msiempy.core.session.NitroSession.request` arguments.  

Used in `msiempy.core.session.NitroSession.request` code.  

Important note : 
    Do not use sigle quotes (`'`) to delimit data into the interpolated strings !

*Partial* data structure :  
```
{
    "login": ("login",
            """{"username": "%(username)s",
                "password" : "%(password)s",
                "locale": "en_US",
                "os": "Win32"}
                """),
    
    "add_watchlist_values": ("""sysAddWatchlistValues""","""{
            "watchlist": %(watchlist)s,
            "values": %(values)s,
            }"""),

    "get_watchlist_values": ("SYS_GETWATCHLISTDETAILS",
                                    """{"WID": "%(id)s", "LIM": "T"}"""),

    "remove_watchlists": ("""sysRemoveWatchlist""", """{"ids": {"watchlistIdList": ["%(wl_id_list)s"]}}"""),

    "get_alert_data": ("""ipsGetAlertData""", """{"id": {"value":"%(id)s"}}"""),
    
    "get_sys_info"  : ("SYS_GETSYSINFO","""{}"""),
    
    "build_stamp" : ("essmgtGetBuildStamp",None),

    "event_query" : ("""qryExecuteDetail?type=EVENT&reverse=false""", """{
                "config": {
                    "timeRange":"%(time_range)s",
                    "fields":%(fields)s,
                    "filters":%(filters)s,
                    "limit":%(limit)s,
                    "offset":%(offset)s,
                    "order": [{"field": {"name": "%(order_field)s"}, "direction": "%(order_direction)s"}]
                    }}"""),

    [...]
}
```  
Please see `dump_api_params.py` script at https://github.com/mfesiem/msiempy/blob/master/samples/dump_api_params.py to dump the complete structure.

Possible `msiempy.core.session.NitroSession.request` requests and arguments: 

'''

class NitroSession():
    """
    `msiempy.core.session.NitroSession` is the point of convergence of every requests that goes to the ESM.  
    It provides easier dialogue with the ESM by doing agument interpolation with `msiempy.core.session.PARAMS`.  

    It uses `msiempy.core.config.NitroConfig` to setup authentication, other configuration like verbosity, logfile, general timeout, are offered throught the config file.

    The init method is called every time you call NitroSession() constructor. But the properties are actually initiated only once.  

    Arguments:  

    - `conf_path` : Configuration file path.  
    - `conf_dict` : Manual config dict. ex: `{'general':{'verbose':True}}`. See `msiempy.core.config.NitroConfig` class to have full details.

    See `msiempy.core.session.NitroSession.esm_request` and `msiempy.core.session.NitroSession.request` for usage.  

    """
    def __init__(self, conf_path=None, conf_dict=None):
        # global log
        self.__dict__ = NitroSession.__unique_state__
        
        #Init properties only once
        if NitroSession.__initiated__ == False :
            NitroSession.__initiated__ = True
            
            #Private attributes
            self._headers={'Content-Type': 'application/json'}
            
            #Config parsing
            self.config = NitroConfig(path=conf_path, config=conf_dict)
            NitroSession.config=self.config

            #Set the logging configuration
            self._init_log(verbose=self.config.verbose,
                quiet=self.config.quiet,
                logfile=self.config.logfile)

            self.api_v = 0
            self.logged_in=False
            self.login_info=dict()

            try :
                requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except : 
                pass
            # logging.getLogger("urllib3").setLevel(logging.ERROR)

    BASE_URL = 'https://{}/rs/esm/'
    """API v2 base url: 'https://{}/rs/esm/'"""

    BASE_URL_PRIV = 'https://{}/ess/'
    """Private API base URL: 'https://{}/ess/'"""

    __initiated__ = False
    """
    Weither the session has been intaciated. It's supposed to be a singleton.
    """
    __unique_state__ = {}
    """
    The singleton unique state.
    """
    
    config = None
    """
    `msiempy.core.config.NitroConfig` object.  
    """
    
    PARAMS = PARAMS
        
    def __str__(self):
        return repr(self.__unique_state__) 

    def login(self, retry=1):
        """Authentication is done lazily upon the first call to `msiempy.core.session.NitroSession.request` method, but you can still do it manually by calling this method.  
        Throws `msiempy.NitroError` if login fails.  
        """
        userb64 = tob64(self.config.user)
        passb64 = self.config.passwd
        
        resp = self.request('login', username=userb64, password=passb64, raw=True, secure=True)
        
        if resp != None :
            try:
                resp.raise_for_status()
            except requests.HTTPError as e :
                if retry>0:
                    time.sleep(1)
                    return self.login(retry=retry-1)
                else:
                    raise NitroError('ESM Login Error: ', resp.text) from e
       
            self._headers['Cookie'] = resp.headers.get('Set-Cookie')
            self._headers['X-Xsrf-Token'] = resp.headers.get('Xsrf-Token')
            
            self.user_tz_id = dict(resp.json())['tzId']
            self.logged_in = True
            self.login_info=self.unpack_resp(resp)

            # Shorthanding the API version check 
            # 1 for pre 11.2.1, 2 for 11.2.1 and later
            # Not be confused with the ESM API v1 and v2 which are different.
            if str(self.version).startswith(('9', '10', '11.0', '11.1')):
                self.api_v = 1
            else:
                self.api_v = 2

            log.info('Logged into ESM {} with username {}. Last login {}'.format(
                str(self.config.host),
                self.login_info['userName'],
                self.login_info['lastLoginDate']))

            return True
        else:
            raise NitroError('ESM Login Error: Response empty')

    def logout(self):
        """ 
        This method will logout the session.
        """
        self.api_v = 0
        self.request('logout', http='delete')
        self.logged_in=False
        self.login_info=dict()
        self._headers={'Content-Type': 'application/json'}
        self.user_tz_id = None

    def esm_request(self, method, data, http='post', callback=None, raw=False, secure=False, retry=1):
        """
        Handle a lower level HTTP request to ESM API endpoints.  

        Format the request, handle the basic parsing of the SIEM result as well as other errors.  

        All upper cases method names signals to use the private API methods. 
        See `msiempy.core.session.NitroSession.format_priv_resp` and `msiempy.core.session.NitroSession.format_params`

        ESM responses are unpacked with `msiempy.core.session.NitroSession.unpack_resp`.  

        Arguments :  

        - `method` : ESM API enpoint name and url formatted parameters  
        - `http`: HTTP method.  
        - `data` : dict data to send  
        - `callback` : function to apply afterwards  
        - `raw` : If true will return the Response object from requests module. No retry when raw=True.     
        - `secure` : If true will not log the content of the request.   
        - `retry` : Number of time the request can be retried  

        Returns : 

        - a `dict`, `list` or `str` object. 
        - the `resquest.Response` object if raw=True  
        - `None` if Timeout or TooManyRedirects if raw=False  

        Raises:

        - `msiempy.core.session.NitroError` if any `HTTPError`

        Note : Private API is under /ess/ and public api is under /rs/esm  

        Exemple call:

            from msiempy import NitroSession
            s = NitroSession()
            s.login()
            # qryGetFilterFields 
            s.esm_request('qryGetFilterFields')
            # Get all last 24h alarms details with ESM API v2.  
            alarms = s.esm_request('v2/alarmGetTriggeredAlarms?triggeredTimeRange=LAST_24_HOURS&status=&pageSize=500&pageNumber=1', None)
            for a in alarms:
                a.update(s.esm_request('v2/notifyGetTriggeredNotificationDetail', {'id':a['id']}))

        """

        url=str()
        privateApiCall=False
        result=None

        #Logging the data request if not secure | Logs anyway the method
        log.debug('Requesting HTTP '+str(http)+' '+ str(method) + 
            (' with data '+str(data) if not secure else ' ***') )
        
        http_data=str()

        #Handling private API calls formatting
        if method == method.upper():
            privateApiCall=True
            url = self.BASE_URL_PRIV
            http_data = self.format_params(method, **data)
            log.debug('Private API call : '+str(method)+' Formatted params : '+str(http_data))
        
        #Normal API calls
        else:
            url = self.BASE_URL
            if data :
                http_data = json.dumps(data)

        try :
            result = requests.request(
                http,
                urllib.parse.urljoin(url.format(self.config.host), method),
                data=http_data, 
                headers=self._headers,
                verify=self.config.ssl_verify,
                timeout=self.config.timeout,
                # Uncomment for debugging.
                # proxies={"http": "http://127.0.0.1:8888", "https":"http:127.0.0.1:8888"}
            )

            if raw :
                log.debug('Returning raw requests Response object : '+str(result))
                return result

            else:
                try:
                    result.raise_for_status()

                except requests.HTTPError as e :
                    error=None

                    if retry>0 :
                        # Invalid session handler -> re-login
                        if any([match in result.text for match in ['ERROR_InvalidSession', 'ERROR_INVALID_SESSION',
                            'Not Authorized User', 'Invalid Session', 'Username and password cannot be null']]):
                            error = NitroError('Authentication error with method ({}) and data : {} logging in and retrying esm_request(). From requests.HTTPError {} {}'.format(
                                method, data, e, result.text))
                            log.warning(error)
                            self.logged_in=False
                            self.login()
                        
                        else: log.warning('An HTTP error occured ({} {}), retrying esm_request()'.format(e, result.text))
                        
                        # Retry request
                        time.sleep(1)
                        return self.esm_request(method, data, http, callback, raw, secure, retry=retry-1)
                    
                    else :
                        error = NitroError('Error with method ({}) and data : {}. From requests.HTTPError {} {}'.format(
                            method, data, e, result.text))
                        log.error(error)
                        raise error from e

                else: # The result is not an HTTP Error
                    response = result
                    result = self.unpack_resp(result)

                    if privateApiCall :
                        result = self.format_priv_resp(result)

                    if callback:
                        result = callback(result)

                    log.debug('{} -> Result ({}): {}'.format(
                        str(response),
                        type(result),
                        str(result)[:200] + '[...]' if len(str(result))>200 else ''
                    ))

                    return result

        #Hard errors, could retry
        except requests.exceptions.Timeout as e:
            log.error(e)
            raise
        except requests.exceptions.TooManyRedirects as e :
            log.error(e)
            raise
        
    # def _request_http_error_handler(self, error, method, data, http, callback, raw, secure, retry):
    #     pass

    def version(self):
        """
        Returns: `str` ESM short version.  
        Example: '10.0.2'
        """
        return self.buildstamp().split()[0]

    def buildstamp(self):
        """
        Returns: `str` ESM buildstamp.  
        Example: '10.0.2 20170516001031'
        """
        return self.request('build_stamp')['buildStamp']

    def get_internal_file(self, file_token):
        """Uses the private API to retrieve, assemble and delete a temp file from the ESM.
        
        Arguments:  

        - `file_token` (`str`): File token ID
        """
        pos = 0
        nbytes = 0
        resp = self.request('get_rfile2', ftoken=file_token, pos=pos, nbytes=nbytes)

        if resp['FSIZE'] == resp['BREAD']:
            data = resp['DATA']
            self.request('del_rfile', ftoken=file_token)
            return data
        
        data = []
        data.append(resp['DATA'])
        file_size = int(resp['FSIZE'])
        collected = int(resp['BREAD'])

        while file_size > collected:
            pos += int(resp['BREAD'])
            nbytes = file_size - collected
            resp = self.request('get_rfile2', ftoken=file_token, pos=pos, nbytes=nbytes)
            collected += int(resp['BREAD'])
            data.append(resp['DATA'])

        resp = self.request('del_rfile', ftoken=file_token)
        return ''.join(data)

    def request(self, request, **kwargs):
        """
        Interface to make ESM API calls more simple by interpolating `**kwargs` arguments with `msiempy.core.session.PARAMS` docstrings and build a valid datastructure for the HTTP data.  

        Then call the `msiempy.core.session.NitroSession.esm_request` method with the built data.  

        Also handles auto-login.  

        Arguments:  

        - `request`: Keyword corresponding to the request name in `msiempy.core.session.PARAMS` mapping.  
        - `http`: HTTP method.  
        - `callback` : function to apply afterwards  
        - `raw` : If true will return the Response object from requests module.   
        - `secure` : If true will not log the content of the request.   
        - `retry` : Number of time the request can be retried
        
        Interpolation parameters :  
        
        - `**kwargs` : Interpolation parameters that will be match to `msiempy.core.session.PARAMS` templates. Dynamic keyword arguments.  

        Returns :  

        - a `dict`, `list` or `str` object  
        - the `resquest.Response` object if raw=True  
        - `result.text` if `requests.HTTPError`,   
        - `None` if Timeout or TooManyRedirects if raw=False  

        Exemple call:

            from msiempy import NitroSession
            s = NitroSession()
            s.login()
            # Get all last 24h alarms details
            alarms = s.request('get_alarms', time_range='LAST_24_HOURS',  status='', page_size=500, page_number=0)
            for a in alarms:
                a.update(s.request('get_alarm_details_new', id=a['id']))


        """
        log.debug("Calling nitro request : {} kwargs={}".format(
            str(request), '***' if 'secure' in kwargs and kwargs['secure']==True else str(kwargs)))

        method, data = self.PARAMS.get(request)

        if data != None :
            data =  data % kwargs
            data = ast.literal_eval((data.replace('\n','').replace('\t','')))
           
        if method != None:
            try :
                method = method % kwargs
            except TypeError as err :
                if ('must be real number, not dict' in str(err)):
                    log.warning("Interpolation failed probably because of the private API calls formatting... Unexpected behaviours can happend.")

        if not self.logged_in and method != 'login':
            # Autologin
            self.login()
    
        # Dynamically checking the esm_request arguments so additionnal parameters can be passed.  
        esm_request_args = inspect.getfullargspec(self.esm_request)[0]
        params={}
        for arg in kwargs :
            if arg in esm_request_args:
                params[arg]=kwargs[arg]
        return self.esm_request(method=method, data=data, **params)

    @staticmethod
    def _init_log(verbose=False, quiet=False, logfile=None):
        """
        Private method. Inits the session's logger settings based on params
        All objects should be able to log stuff, so the logger is globaly accessible
        """

        log.setLevel(logging.DEBUG)

        std = logging.StreamHandler()
        std.setLevel(logging.DEBUG)
        std.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))

        if verbose :
            std.setLevel(logging.DEBUG)
        elif quiet :
            std.setLevel(logging.CRITICAL)
        else :
            std.setLevel(logging.INFO)

        log.handlers=[]
        
        log.addHandler(std)

        if logfile :
            fh = logging.FileHandler(logfile)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            log.addHandler(fh)

        if verbose and quiet :
            log.warning("Verbose and quiet values are both set to True. By default, output will be verbose.")

        return (log)

    @staticmethod
    def format_params(cmd, **params):
        """
        Format private API call.  
        """
        params = {k: v for k, v in params.items() if v != None}
        params = '%14'.join([k + '%13' + v + '%13' for (k, v) in params.items()])
        
        if params:
            params = 'Request=API%13' + cmd + '%13%14' + params + '%14'
        else:
            params = 'Request=API%13' + cmd + '%13%14'
        return params

    @staticmethod
    def format_priv_resp(resp):
        """
        Format response from private API.  
        """
        resp = re.search('Response=(.*)', resp).group(1)
        resp = resp.replace('%14', ' ')
        pairs = resp.split()
        formatted = {}
        for pair in pairs:
            pair = pair.replace('%13', ' ')
            pair = pair.split()
            key = pair[0]
            if key == 'ITEMS':
                value = pair[-1]
            else:
                value = urllib.parse.unquote(pair[-1])
            formatted[key] = value
        return formatted

    @staticmethod
    def unpack_resp(response) :
        """Unpack data from response.  
        Should not be necessary with API v2.  
        Args: 
            response: requests.Response response object
        Returns a list, a dict or a string
        """
        try :
            data = response.json()
            if isinstance(response.json(), dict):
                try:
                    data = data['value']
                except KeyError:
                    try:
                        data = data['return']
                    except KeyError:
                        pass
            
        except ValueError :
            data = response.text

        return data

class NitroError(Exception):
    """
    Base ESM exception.  
    It's used when the user/passwd is incorrect and other HTTP errors.  
    """
    pass
