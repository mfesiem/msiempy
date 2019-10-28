# -*- coding: utf-8 -*-
"""# Welcome to the **msiempy** module documentation. The pythonic way to deal with McAfee SIEM API.  

GitHub : https://github.com/mfesiem/msiempy  

Classes listed in this module are base to other classes in sub-modules that offers specialized objects and functions.  

This API offers two main types of objects to interact with the SIEM : `msiempy.NitroList`, `msiempy.NitroDict`. 
`msiempy.NitroList`s have default behaviours related to parallel execution, string representation generation and search feature.
Whereas `msiempy.NitroDict` that doesn't have any specific behaviours. Both inheriths from `msiempy.NitroObject` that handle a reference to a single `msiempy.NitroSession` object.  

`msiempy.NitroSession` is the point of convergence of every request to the McFee ESM It provides standard dialogue with the esm.
It uses `msiempy.NitroConfig` to setup authentication, other configuration like verbosity, logfile, general timeout, are offered throught the config file.  

Class diagram : https://mfesiem.github.io/docs/msiempy/classes.png  
Packages : https://mfesiem.github.io/docs/msiempy/packages.png  

Only working with SIEM version >=11.2.1 (and maybe >=10.4.1)
"""

import logging
import requests
import json
import ast
import re
import urllib.parse
import urllib3
import configparser
import os
import getpass
import abc
import collections
import tqdm
import copy
import csv
import sys
import concurrent.futures
import prettytable
from prettytable import MSWORD_FRIENDLY
import datetime
import functools
import textwrap
import inspect
import time

from io import StringIO
from .__utils__ import regex_match, tob64, format_esm_time, convert_to_time_obj, timerange_gettimes, parse_timedelta, divide_times


try :
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except : pass

logging.getLogger("urllib3").setLevel(logging.WARNING)
log = logging.getLogger('msiempy')

__pdoc__={} #Init pdoc overwrite engine to document stuff dynamically

class NitroError(Exception):
    """
    Base internal exception. It's used when the user/passwd is incorrect, or other specific ESM related errors.
    """
    pass

class NitroConfig(configparser.ConfigParser):
    """Class that handles the configuration. Reads the config file where ever it is and make accessible it's values throught object properties. 
    If a `.msiem/` directory exists in your current directory, the program will assume the `conf.ini` file is there, if not, it will create it with default values. 
    Secondly, if no `.msiem/` directory exists in the current directory, it will be automatically placed in a appropriate place depending of your platform:  

    For Windows: `%APPDATA%\.msiem\conf.ini`
    For Mac : `$HOME/.msiem/conf.ini`
    For Linux : `$XDG_CONFIG_HOME/.msiem/conf.ini` or : `$HOME/.msiem/conf.ini`
    If `.msiem` folder exists in you local directory : `./.msiem/conf.ini`

    """

    CONFIG_FILE_NAME='.msiem/conf.ini'
    """`.msiem/conf.ini`"""

    CONF_DIR='.msiem/'
    """`.msiem/`"""

    DEFAULT_CONF_DICT={
        'esm':{'host':'', 
            'user':'',
            'passwd':''},
        'general':{'verbose':False,
            'quiet':False,
            'logfile':'',
            'timeout':30,
            'ssl_verify':False,
            'output':'text'}
    }
    """Default configuration file should look like this. Authentication is left empty.
    ```
    [esm]
    host = 
    user = 
    passwd = 

    [general]
    verbose = False
    quiet = False
    logfile = 
    timeout = 30
    ssl_verify = False
    output = text #Not used yet
    ```
    """

    def __str__(self):
        """Custom str() method that lists all config fields.
        """
        return('Configuration file : '+ self._path+'\n'+str({section: dict(self[section]) for section in self.sections()}))

    def __init__(self, path=None, config=None, *arg, **kwarg):
        """Parameters:  

        - `path`: Config file special path, if path is left None, will automatically look for it.  
        - `config`: Manual config dict. ex: `{'general':{'verbose':True}}`.
        - `*args, **kwargs` : Passed to `configparser.ConfigParser.__init__()` method.
        """

        super().__init__(*arg, **kwarg)

        self.read_dict(self.DEFAULT_CONF_DICT)
    
        if not path :
            self._path = self.find_ini_location()
        else : 
            self._path = path

        try :
            files=self.read(self._path)
            if len(files) == 0:
                raise FileNotFoundError

        except :
            log.info("Config file inexistant or currupted, applying defaults")

            if not os.path.exists(os.path.dirname(self._path)):
                os.makedirs(os.path.dirname(self._path))
            self.write()

        if config is not None :
            log.info("Reading config_dict : "+str(self))
            self.read_dict(config)

    def write(self):
        """Write the config file to the predetermined path.
        """
        log.info("Write config file at "+self._path)
        with open(self._path, 'w') as conf:
            super().write(conf)

    def _iset(self, section, option, secure=False):
        """Internal method to interactively set  a option in a section.
        """
        msg='Enter [{}]{}'
        value = self.get(section, option)
        newvalue=''
        if option=='passwd':
            secure=True
        if secure :
            newvalue = tob64(getpass.getpass(msg.format(section, option)+'. Press <Enter> to skip: '))
        else:
            newvalue = input(msg.format(section, option)+ '. Press <Enter> to keep '+ (value if (str(value) is not '') else 'empty') + ': ')
        if newvalue != '' :
            super().set(section, option, newvalue)

    def iset(self, section, option=None, secure=False):
        """Interactively set the specified section/option by asking the user the input.  
        Parameters:  

        - `section`: Configuration's section. Exemple : 'esm' or 'general'.  
        - `option`: Configuraion's option. Leave to `None` to set the whole section one after another. Exemple : 'user', 'timeout'.  
        - `secure`: Will use getpass to retreive the configuration value and won't print old value.
        """
        if option is None :
            for key in self.options(section):
                self._iset(section, key, secure)
        else :
            self._iset(section, option, secure)

    @property
    def user(self): return self.get('esm', 'user')

    @property
    def host(self): return self.get('esm', 'host')

    @property
    def passwd(self): return self.get('esm', 'passwd')

    @property
    def verbose(self): return self.getboolean('general', 'verbose')

    @property
    def quiet(self): return self.getboolean('general', 'quiet')

    @property
    def logfile(self): return self.get('general', 'logfile')

    @property
    def timeout(self): return self.getint('general', 'timeout')

    @property
    def ssl_verify(self): return self.getboolean('general', 'ssl_verify')

    @property
    def output(self): return self.get('general', 'output')

   
    @staticmethod
    def find_ini_location():
        '''
        Returns the location of a supposed conf.ini file the `conf.ini` file.  
        If `.msiem` folder exists in you local directory, assume the `conf.ini` file is in there.
        If the file doesn't exist, will still return the location.
        Do not create a file nor directory, you must call `msiempy.NitroConfig.write`.
        '''
        conf_path_dir=None

        if os.path.isdir('./'+NitroConfig.CONF_DIR):
            conf_path_dir='./'

        elif 'APPDATA' in os.environ:
                conf_path_dir = os.environ['APPDATA']

        elif 'XDG_CONFIG_HOME' in os.environ:  
            conf_path_dir = os.environ['XDG_CONFIG_HOME']

        elif 'HOME' in os.environ:  
            conf_path_dir = os.path.join(os.environ['HOME'])
            
        else:
            conf_path_dir='./'
        
        #Join configuartion filename with supposed parent directory
        conf_path=(os.path.join(conf_path_dir, NitroConfig.CONFIG_FILE_NAME))

        return(conf_path)

class NitroSession():
    '''NitroSession object represent the point of convergence of every request to the McFee ESM
    It provides standard dialogue with the esm with agument interpolation with `msiempy.NitroSession.PARAMS`.
    Internal `__dict__` refers to a unique instance of dict and thus, properties can be instanciated only once. 
    '''

    BASE_URL = 'https://{}/rs/esm/'
    __pdoc__['NitroSession.BASE_URL']="""API v2 base url: `%(url)s`""" % dict(url=BASE_URL)

    BASE_URL_PRIV = 'https://{}/ess/'
    __pdoc__['NitroSession.BASE_URL_PRIV']="""Private API base URL: `%(url)s`""" % dict(url=BASE_URL_PRIV)

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
    `msiempy.NitroConfig` object.
    """
    
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
                    """{"DATA1": "%(_ds_id)s",
                    """),
        
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

        "add_client": ("DS_ADDDSCLIENT", 
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
                        "USETLS": "%(syslog_tls)s"
                        }"""),
                        
        "get_recs": ("devGetDeviceList?filterByRights=false",
                        """{"types": ["RECEIVER"]}
                        """),

        "get_dstypes": ("dsGetDataSourceTypes",
                        """{"receiverId": {"id": "%(rec_id)s"}
                            }
                        """),
                        
        "del_ds": ("dsDeleteDataSource",
                    """{"receiverId": {"id": "%(parent_id)s"},
                        "datasourceId": {"id": "%(ds_id)s"}}
                    """),
                    
        "del_client": ("DS_DELETEDSCLIENTS",None
                        ),
                        
        "ds_last_times": ("QRY%5FGETDEVICELASTALERTTIME","""{}"""),
                        
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
                            
            "ds_details": ("dsGetDataSourceDetail",
                            """{"datasourceId": 
                                {"id": "%(ds_id)s"}}
                            """),

            "get_alarms_custom_time": ("""alarmGetTriggeredAlarms?triggeredTimeRange=%(time_range)s&customStart=%(start_time)s&customEnd=%(end_time)s&status=%(status)s&pageSize=%(page_size)s&pageNumber=%(page_number)s""",
                        None),

            "get_alarms": ("""alarmGetTriggeredAlarms?triggeredTimeRange=%(time_range)s&status=%(status)s&pageSize=%(page_size)s&pageNumber=%(page_number)s""", None),

            "get_alarm_details": ("""notifyGetTriggeredNotification""", """{"id":%(id)s}"""),
            
            "get_alarm_details_int": ("NOTIFY_GETTRIGGEREDNOTIFICATIONDETAIL", 
                                        """{"TID": "%(id)s"}"""),

            "ack_alarms": ("""alarmAcknowledgeTriggeredAlarm""", """{"triggeredIds":{"alarmIdList":%(ids)s}}"""),

            "unack_alarms": ("""alarmUnacknowledgeTriggeredAlarm""", """{"triggeredIds":{"alarmIdList":%(ids)s}}"""),

            "delete_alarms": ("""alarmDeleteTriggeredAlarm""", """{"triggeredIds":{"alarmIdList":%(ids)s}}"""),
            
            "get_possible_filters" : ( """qryGetFilterFields""", None ),

            "get_possible_fields" : ( """qryGetSelectFields?type=%(type)s&groupType=%(groupType)s""", None ),

            "get_esm_time" : ( """essmgtGetESSTime""",None),

            "logout" : ( """userLogout""", None ),

            "get_user_locale" : ( """getUserLocale""", None ),

            "event_query_custom_time" : ("""qryExecuteDetail?type=EVENT&reverse=false""", """{
                    "config": {
                        "timeRange": "%(time_range)s",
                        "customStart": "%(start_time)s",
                        "customEnd": "%(end_time)s",
                        "fields":%(fields)s,
                        "filters":%(filters)s,
                        "limit":%(limit)s,
                        "offset":%(offset)s
                        }
                        }"""),

            "event_query" : ("""qryExecuteDetail?type=EVENT&reverse=false""", """{
                    "config": {
                        "timeRange":"%(time_range)s",
                        "fields":%(fields)s,
                        "filters":%(filters)s,
                        "limit":%(limit)s,
                        "offset":%(offset)s
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
    __pdoc__['NitroSession.PARAMS'] = """This structure provide a central place to aggregate API methods and parameters. 
    The parameters are stored as docstrings to support string replacement.  

    Args:  
        method (str): Dict key associated with desired function
        Use normal dict access, PARAMS["method"], or PARAMS.get("method")

    Returns:  
        - `tuple `: (string, string) : The first string is the method name that is actually used as
        the URI or passed to the ESM. The second string is the params
        required for that method. Some params require variables be
        interpolated as documented in the Attributes.

    Example:
        `method, params = PARAMS.get("login").format(username, password)`. See : `msiempy.NitroSession.request`

    Important note : 
        Do not use sigle quotes (') to delimit data into the interpolated strings !

    Content :
        %(content)s
        """ % dict(content=json.dumps(PARAMS, indent=4).replace('\n',"""  
    """)[:130]+""" [...] and more..  
    See : https://github.com/mfesiem/msiempy/blob/master/msiempy/__init__.py#L266
    """)
        
    def __str__(self):
        return repr(self.__unique_state__) 

    def __init__(self, conf_path=None, conf_dict=None):
        """
        The init method is called every time you call NitroSession() constructor.
        But the properties are actually initiated only once.
        Use logout() to reinstanciate NitroSession.  

        Parameters:  

        - `conf_path` : Configuration file path.  
        - `conf_dict` : Manual config dict. ex: `{'general':{'verbose':True}}`. See `msiempy.NitroConfig` class to have full details.
        """
        global log
        self.__dict__ = NitroSession.__unique_state__
        
        #Init properties only once
        if NitroSession.__initiated__ == False :
            NitroSession.__initiated__ = True
            
            #Private attributes
            self._headers={'Content-Type': 'application/json'}
            self._logged=False
            
            #Config parsing
            self.config = NitroConfig(path=conf_path, config=conf_dict)
            NitroSession.config=self.config

            #Set the logging configuration
            self._init_log(verbose=self.config.verbose,
                quiet=self.config.quiet,
                logfile=self.config.logfile)

            log.info('New ESM session instance is created with : '+str(self.config.host))


    def esm_request(self, method, data, http='post', callback=None, raw=False, secure=False, retry=True):
        """
        Helper method that format the request, handle the basic parsing of the SIEM result as well as other errors.          
        If method is all upper cases, it's going to be formatted as a private API call. See `msiempy.NitroSession.format_params` and `msiempy.NitroSession.format_priv_resp` 
        In any way, the ESM response is unpacked by `msiempy.NitroSession.unpack_resp`

        Parameters :
            - `method` : ESM API enpoint name and url parameters  
            - `http`: HTTP method.  
            - `data` : dict data to send  
            - `callback` : function to apply afterwards  
            - `raw` : If true will return the Response object from requests module.   
            - `secure` : If true will not log the content of the request.   

        Returns : 
            - a `dict`, `list` or `str` object  
            - the `resquest.Response` object if raw=True  
            - `result.text` if `requests.HTTPError`,   
            - `None` if Timeout or TooManyRedirects if raw=False  

         Note : Private API is under /ess/ and public api is under /rs/esm  

        """

        url=str()
        privateApiCall=False
        result=None

        #Logging the data request if not secure | Logs anyway the method
        log.debug('Requesting HTTP '+str(http)+' '+ str(method) + 
            (' with data '+str(data) if not secure else ' ***') )
        
        #Handling private API calls formatting
        if method == method.upper():
            privateApiCall=True
            url = self.BASE_URL_PRIV
            data = self.format_params(method, **data)
            log.debug('Private API call : '+str(method)+' Formatted params : '+str(data))
        
        #Normal API calls
        else:
            url = self.BASE_URL
            if data:
                data = json.dumps(data)

        try :
            result = requests.request(
                http,
                urllib.parse.urljoin(url.format(self.config.host), method),
                data=data, 
                headers=self._headers,
                verify=self.config.ssl_verify,
                timeout=self.config.timeout,
                # Uncomment for debugging.
                #proxies={"http": "http://127.0.0.1:8888", "https":"http:127.0.0.1:8888"}
            )

            if raw :
                log.debug('Returning raw requests Response object : '+str(result)+ ' ' + str(result.text))
                return result

            else:
                try:
                    result.raise_for_status()
                except requests.HTTPError as e :

                    if retry == True :
                        if 'ERROR_InvalidSession' in result.text :
                            log.warning('Invalid session, retrying with authentication')
                            self._logged=False
                            self.login()
                        else:
                            log.warning('An HTTP error occured ({}), retrying request'.format(result.text))

                        time.sleep(0.2)
                        return self.esm_request(method, data, http, callback, raw, secure, retry=False)

                    log.error('\n' + str(e)+ ' ' +str(result.text) + '\nSee debug log for more infos.')
                    log.debug(str(e)+ ' ' +str(result.text)+ ' ' + str(result.__dict__))
                    exit(423)
                    
                    """
                    #TODO handle expired session error, result unavailable / other siem errors
                    # _InvalidFilter (228)
                    # _IndexNotTurnedOn (49)
                    # Status Code 500: Error processing request, see server logs for more details 
                    # Input Validation Error
                    # By creating a new class
                    # ERROR_InvalidSession (1)
                    """

                else: #
                    result = self.unpack_resp(result)

                    if privateApiCall :
                        result = self.format_priv_resp(result)

                    if callback:
                        result = callback(result)

                    log.debug('Result '+str(result)[:100]+'[...]')

                    return result

        #Soft errors
        except requests.exceptions.Timeout as e:
            log.error(e)
            return None
        except requests.exceptions.TooManyRedirects as e :
            log.error(e)
            return None
        
    def login(self):
        """Authentication is done lazily upon the first call to `msiempy.NitroSession.request` method, but you can still do it manually by calling this method.  
        Throws `msiempy.NitroError` if login fails
        """
        userb64 = tob64(self.config.user)
        passb64 = self.config.passwd
        
        resp = self.request('login', username=userb64, password=passb64, raw=True, secure=True)
        
        if resp is not None :
            if resp.status_code in [400, 401]:
                raise NitroError('Invalid username or password for the ESM')
            elif 402 <= resp.status_code <= 600:
                raise NitroError('ESM Login Error:', resp.text)
       
            self._headers['Cookie'] = resp.headers.get('Set-Cookie')
            self._headers['X-Xsrf-Token'] = resp.headers.get('Xsrf-Token')
    
            self._logged=True
            return True
        else:
            raise NitroError('ESM Login Error: Response empty')

    def version(self):
        """
        Returns:
            str. ESM short version.

        Example:
            '10.0.2'
        """
        return self.buildstamp().split()[0]

    def buildstamp(self):
        """
        Returns:
            str. ESM buildstamp.

        Example:
            '10.0.2 20170516001031'
        """
        return self.request('build_stamp')['buildStamp']


    def request(self, request, **kwargs):
        """
            This method is the centralized interface of all requests going to the SIEM.  
            It interpolates `**params` with `msiempy.NitroSession.PARAMS` docstrings and build a valid datastructure with `ast`.  
            Wrapper around the `msiempy.NitroSession.esm_request` method.  

            Parameters:  

            - `request`: Keyword corresponding to the request name in `msiempy.NitroSession.PARAMS` mapping.  
            - `**kwargs` Can contain :
                - `msiempy.NitroSession.esm_request` arguments except `method` and `data`
                - Interpolation parameters that will be match to `msiempy.NitroSession.PARAMS` templates. Check the file to be sure of the keyword arguments.  

            Returns : 
            - a `dict`, `list` or `str` object  
            - the `resquest.Response` object if raw=True  
            - `result.text` if `requests.HTTPError`,   
            - `None` if Timeout or TooManyRedirects if raw=False  
        """
        log.debug("Calling nitro request : {} kwargs={}".format(
            str(request), '***' if 'secure' in kwargs and kwargs['secure']==True else str(kwargs)))

        method, data = self.PARAMS.get(request)

        if data is not None :
            data =  data % kwargs
            data = ast.literal_eval((data.replace('\n','').replace('\t','')))
           
        if method is not None:
            try :
                method = method % kwargs
            except TypeError as err :
                if ('must be real number, not dict' in str(err)):
                    log.warning("Interpolation failed probably because of the private API calls formatting... Unexpected behaviours can happend.")

        if not self._logged and method != 'login':
            self.login()
            self.version = self.version()
        try :
            #Dynamically checking the esm_request arguments so additionnal parameters can be passed afterwards.
            esm_request_args = inspect.getargspec(self.esm_request)[0]
            params={}
            for arg in kwargs :
                if arg in esm_request_args:
                    params[arg]=kwargs[arg]
            return self.esm_request(method=method, data=data, **params)

        except ConnectionError as e:
            log.critical(e)
            raise
        except Exception as e:
            log.error(e)
            raise 
        
    def logout(self):
        """ 
        This method will logout the session, clear headers and throw away the object,
            a new session will be instanciated next time.
        """
        self.request('logout', http='delete')
        self._logged=False

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
            log.warning("Verbose and quiet values are both set to True. This is a very inconsistent state. By default, verbose value has priority.")

        return (log)
    

    @staticmethod
    def format_params(cmd, **params):
        """
        Format private API call.  
        From mfe_saw project at https://github.com/andywalden/mfe_saw
        """
        params = {k: v for k, v in params.items() if v is not None}
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
        From mfe_saw project at https://github.com/andywalden/mfe_saw
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
            
        except json.decoder.JSONDecodeError:
            data = response.text

        return data

class NitroObject(abc.ABC):
    """
    Base class for all nitro objects. All objects have a reference to the single `msiempy.NitroSession` object that handle the esm requests.
    """

    class NitroJSONEncoder(json.JSONEncoder):
        """
        Custom JSON encoder that will use the approprtiate propertie depending of the type of NitroObject.  
        TODO return meta info about the NitroList. Maybe create a section `manager` and `data`.  
        TODO support json json dumping of QueryFilers, may be by making them inherits from NitroDict.  
        """
        def default(self, obj): # pylint: disable=E0202
            if isinstance(obj,(NitroDict, NitroList)):
                return obj.data
            #elif isinstance(obj, (QueryFilter)):
                #return obj.config_dict
            else:
                return json.JSONEncoder.default(self, obj) 

    @abc.abstractmethod
    def __init__(self):
        """Creates the object session.
        """
        self.nitro=NitroSession()

    def __str__(self):
        """str(obj) -> return text string.
        Can be a table if the object is a NitroList.
        """
        return self.text

    def __repr__(self):
        """repr(obj) -> return json string.
        """
        return self.json

    @abc.abstractproperty
    def text(self):
        """Returns printable string.
        """
        pass

    @abc.abstractproperty
    def json(self):
        """Returns json string representation.
        """
        pass

    @abc.abstractmethod
    def refresh(self):
        """Refresh the state of the object.
        """
        pass

class NitroDict(collections.UserDict, NitroObject):
    """
    Base class that represent any SIEM data that can be represented as a item of a list.
    Exemple : Event, Alarm, etc...
    Inherits from dict.
    """
    def __init__(self, adict=None, id=None):
        """
        Initiate the NitroObject and UserDict objects, load the data if id is specified, use adict agument 
        and update dict values accordingly.

        Parameters:  

        - `adict`: dict object to wrap.  
        - `id`: ESM obejct unique identifier. Alert.IPSIDAlertID for exemple. 
        """
        NitroObject.__init__(self)
        collections.UserDict.__init__(self, adict)
        
        if id != None :
            self.data=self.data_from_id(id)

        if isinstance(adict, dict):
            self.data=adict

        for key in self.data :
            if isinstance(self.data[key], list):
                self.data[key]=NitroList(alist=self.data[key])

    @property
    def json(self):
        """JSON representation of a item. Basic dict.
        """
        return(json.dumps(dict(self), indent=4, cls=NitroObject.NitroJSONEncoder))

    @property
    def text(self):
        """A list of values. Not titles.
        """
        return(', '.join([str(val) for val in self.values()]))

    def refresh(self):
        """Not implemented here
        """
        log.debug('NOT Refreshing item :'+str(self)+' '+str(NotImplementedError()))

    @abc.abstractmethod
    def data_from_id(self, id):
        """This method figured out the way to retreive the item infos from an id.
        """
        pass

class NitroList(collections.UserList, NitroObject):
    """
    Base class for NitroList objects. It offers callable execution management, search and other data list actions.  
    TODO better polymorphism to cast every sub-NitroList class's item dynamcally in `__init__` method
    """

    def __init__(self, alist=None):
        """
        Parameters:  

        - `alist`: list object to wrap.
        """
        NitroObject.__init__(self)
        if alist is None:
            collections.UserList.__init__(self, [])
        
        elif isinstance(alist , (list, NitroList)):
            collections.UserList.__init__(
                self, alist #[NitroDict(adict=item) for item in alist if isinstance(item, (dict, NitroDict))] 
                #Can't instanciate NitroDict, so Concrete classes have to cast the items afterwards!
                #TODO better polymorphism to cast every sub-NitroList class's item dynamcally !
                )
        else :
            raise ValueError('NitroList can only be initiated based on a list')

    def _norm_dicts(self):
        """
        Internal method.
        All dict should have the same set of keys.
        Creating keys in dicts.
        """
        for item in self.data :
            if isinstance(item, (dict, NitroDict)):
                for key in self.keys :
                    if key not in item :
                        item[key]=None

    @property
    def keys(self):
        """Set of keys for all dict
        """
        #If new fields are added it won't show on text repr. Only json.
        
        manager_keys=set()
        for item in self.data:
            if isinstance(item, (dict,NitroDict)):
                manager_keys.update(item.keys())

        return manager_keys


    def get_text(self, format='pprint', fields=None, 
                        max_column_width=120, get_text_nest_attr={}):
        """
        Return a acsii table string representation of the manager list

        Parameters:  

        - `format`: 
              pprint: Returns a spaced table separated by |
              compact: Returns a non-spaced table separated by |
              csv: Returns data with header and comma separated values. 
              
        - `fields`: list of fields you want in the table is None : default fields are returned by .keys attribute and sorted.  
        - `max_column_width`: when using prettytable (not compact)  
        - `get_text_nest_attr`: attributes passed to the nested NitroList elements. Useful to control events appearence.

        It's an expesive thing to do on big ammount of data !
        """
        
        if not fields :
            fields=sorted(self.keys)

        if len(self) == 0 :
            return('The list is empty')

        if format == 'csv':
            file = StringIO()
            dw = csv.DictWriter(file, self.data[0].keys())
            dw.writeheader()
            dw.writerows(self.data)
            text = file.getvalue()
        elif format == 'compact':
            text='|_'
            for field in fields :
                text+=field
                text+='_|_'
            text=text[0:len(text)-1]
            text+='\n'
            for item in self.data:
                if isinstance(item, (dict, NitroDict)):
                    text+='| '
                    for field in fields :
                        if isinstance(item[field], NitroList):
                            text+=item[field].get_text(format='compact')
                        else:
                            text+=(str(item[field]))
                            text+=' | '
                    text=text[0:len(text)-1]
                else : log.warning("Unnapropriate list element type, doesn't show on the list : {}".format(str(item)))
                    #text+=textwrap.wrap(str(item),width=max_column_width)
                text+='\n'
            text=text[0:len(text)-1]
            
        else:
            table = prettytable.PrettyTable()
            table.set_style(MSWORD_FRIENDLY)
            table.field_names=fields
            self._norm_dicts()

            for item in self.data:
                if isinstance(item, (dict, NitroDict)):
                    try :
                        table.add_row(['\n'.join(textwrap.wrap(str(item[field]), width=max_column_width))
                            if not isinstance(item[field], NitroList)
                            else item[field].get_text(**get_text_nest_attr) for field in fields])
                    
                    except (KeyError, IndexError) as err :
                        log.error("Inconsistent NitroList state, some fields aren't present in the dict keys. Try calling _norm_dicts() method : "+str(err))
                        raise

                    except Exception as err :
                        if "Row has incorrect number of values" in str(err):
                            log.error("Inconsistent NitroList state, some fields aren't present or too many are present : {}".format(str(err)))
                else : log.warning("Unnapropriate list element type, doesn't show on the list : {}".format(str(item)))
            text=table.get_string()
        return text


    @property
    def text(self):
        """The text property is a shorcut to get_text() with no arguments.
        """
        return self.get_text()
        
    @property
    def json(self):
        """Dumps a JSON list of dicts representing the current list.
        """
        return(json.dumps([dict(item) for item in self.data], indent=4, cls=NitroObject.NitroJSONEncoder))

    def search(self, invert=False, match_prop='json', *pattern):
        """
        Return a list of elements that matches one or more regex patterns.
        Patterns are applied one after another. It's a logic AND.
        Use `|` inside patterns to search with logic OR.
        This method will return a new NitroList with matching data. NitroDicts in the returned NitroList do not
        references the items in the original NitroList.  

        Parameters:  
        
        - `*pattern`: List or string regex patterns to look for.
        - `invert`: Weither or not to invert the search and return elements that doesn't not match search.
        - `match_prop`: Propertie that is going to be called to search. Could be `text` or `json`.


        If you wish to apply more specific filters to NitroList list, please
        use filter(), list comprehension, or other filtering method.
            i.e. : `[item for item in list if item['cost'] > 50]`

        More on regex https://docs.python.org/3/library/re.html#re.Pattern.search
        """
        if pattern is None :
            return self
        elif len(pattern) == 0 :
            return self
        else :
            pattern=list(pattern)
            apattern=pattern.pop()
        
        matching_items=list()
        
        if isinstance(apattern, str):
            for item in self.data :
                if regex_match(apattern, getattr(item, match_prop) if isinstance(item, NitroDict) else str(item)) is not invert :
                    matching_items.append(item)
            log.debug("You're search returned {} rows : {}".format(
                len(matching_items),
                str(matching_items)[:100]+'...'))
            #Apply AND reccursively
            return NitroList(alist=matching_items).search(*pattern, invert=invert, match_prop=match_prop)
        else:
            raise ValueError('pattern must be str')

    def refresh(self):
        """
        Execute refresh function on all items.
        """
        log.warning("The function NitroList.refresh hasn't been correctly tested")
        self.perform(NitroDict.refresh)

    def perform(self, func, data=None, func_args=None, confirm=False, asynch=False,  workers=None , progress=False, message=None):
        """
        Wrapper arround executable and the data list of `msiempy.NitroList` object.
        Will execute the callable the list.

        Parameters:  
        
        - `func`: callable stateless function. func is going to be called like `func(item, **func_args)` on all items in data.
        - `data`: if stays None, will perform the action on all rows, else it will perfom the action on the data list.
        - `func_args`: dict that will be passed by default to func in all calls.
        - `confirm`: will ask interactively confirmation.
        - `asynch`: execute the task asynchronously with `msiempy.NitroSession` executor.
        - `workers`: mandatory if asynch is true.
        - `progress`: to show progress bar with ETA (tqdm).
        - `message` : To show to the user.

        Returns a list of returned results
        """

        log.debug('Calling perform func='+str(func)+
            ' data='+str(data)[:100]+
            ' func_args='+str(func_args)+
            ' confirm='+str(confirm)+
            ' asynch='+str(asynch)+
            ' workers='+str(workers)+
            ' progress='+str(progress)+
            ' message='+str(message))

        if not callable(func) :
            raise ValueError('func must be callable')

        #Confirming with user if asked
        if confirm : self._confirm_func(func, str(self))

        #Setting the arguments on the function
        func = functools.partial(func, **(func_args if func_args is not None else {}))
        
        #The data returned by function
        returned=list()

        #Usethe self contained data if not speficed otherwise
        elements=self.data
        if isinstance(data, list) and data is not None:
            elements=data
        else :
            AttributeError('data must be a list')

        #Printing message if specified.
        tqdm_args=dict()

        #The message will appear on loading bar if progress is True
        if progress is True :
            tqdm_args=dict(desc='Loading...', total=len(elements))
            if message is not None:
                tqdm_args['desc']=message
        elif message is not None:
            log.info(message)

        #Runs the callable on list on executor or by iterating
        if asynch == True :
            if isinstance(workers, int) :
                if progress==True :
                    if not self.nitro.config.quiet:
                        #Need to call tqdm to have better support for concurrent futures executor
                        # tqdm would load the whole bar intantaneously and not wait until the callable func returns. 
                        returned=list(tqdm.tqdm(concurrent.futures.ThreadPoolExecutor(
                        max_workers=workers ).map(
                            func, elements), **tqdm_args))
                    else:
                        log.warning("You requested to show perfrom progress but config's quiet value is True, not showing tqdm load bar.")
                        returned=list(concurrent.futures.ThreadPoolExecutor(
                        max_workers=workers ).map(
                            func, elements))
                else:
                    returned=list(concurrent.futures.ThreadPoolExecutor(
                    max_workers=workers ).map(
                        func, elements))
            else:
                raise AttributeError('When asynch == True : You must specify a integer value for workers')
        else :

            if progress==True:
                if not self.nitro.config.quiet:
                    elements=tqdm.tqdm(elements, **tqdm_args)
                else:
                    log.warning("You requested to show perform progress but config's quiet value is True, not showing tqdm load bar.")

            for index_or_item in elements:
                returned.append(func(index_or_item))

        return(returned)

    @staticmethod
    def _confirm_func(func, elements):
        """
        Ask user inut to confirm the calling of `func` on `elements`.
        """
        if not 'y' in input('Are you sure you want to do this '+str(func)+' on '+
        ('\n'+str(elements) if elements is not None else 'all elements')+'? [y/n]: '):
            raise InterruptedError("The action was cancelled by the user.")

class FilteredQueryList(NitroList):
    """
    Base class for query based managers : AlarmManager, EventManager
    FilteredQueryList object can handle time_ranges and time splitting.
    Provide time ranged filtered query wrapper.
    """
    
    DEFAULT_TIME_RANGE="CURRENT_DAY"
    __pdoc__['FilteredQueryList.DEFAULT_TIME_RANGE']="""Default time range : %(default)s""" % dict(default=DEFAULT_TIME_RANGE)

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
    __pdoc__['FilteredQueryList.POSSIBLE_TIME_RANGE']="""
    List of possible time ranges : `%(timeranges)s`""" % dict(timeranges=', '.join(POSSIBLE_TIME_RANGE))

    def __init__(self, time_range=None, start_time=None, end_time=None, filters=None, 
        load_async=True, *arg, **kwargs):
        """
        Abstract base class that handles the time ranges operations, loading data from the SIEM.

        Parameters:  
    
        - `time_range` : Query time range. String representation of a time range. 
            See `msiempy.FilteredQueryList.POSSIBLE_TIME_RANGE`
        - `start_time` : Query starting time, can be a string or a datetime object. Parsed with dateutil.
        - `end_time` : Query endding time, can be a string or a datetime object. Parsed with dateutil.
        - `filters` : List of filters applied to the query.
        - `load_async` : Load asynchonously the sub-queries. Defaulted to True.       
            
        """

        #handled eventual deprecated arguments
        if 'max_query_depth' in kwargs :
            log.warning('Deprecated : `max_query_depth` argument has been removed from FilteredQueryList, it\'s now a specilized EventManager argument only. You can remove this argument.')
            del kwargs['max_query_depth']
        if 'requests_size' in kwargs :
            log.warning('Deprecated : `requests_size` argument has been removed from FilteredQueryList, use `page_size` (Alarms) or `limit` (Events) arguments.')
            del kwargs['requests_size']
        if 'load_async' in kwargs :
            log.warning('Deprecated : `load_async` argument has been removed from FilteredQueryList. Queries are now always loaded asynchronously...')
            del kwargs['load_async']

        super().__init__(*arg, **kwargs)

        
        self.not_completed=False

        #self.nitro.config.default_rows #nb rows per request : eq limit/page_size = requests_size
        #self.nitro.config.max_rows #max nb rows 

        #Declaring attributes and types
        self._time_range=str()
        self._start_time=None
        self._end_time=None

        #self.filters=filters filter property setter should be called in the concrete class
        #TODO find a better solution to integrate the filter propertie

        if start_time is not None and end_time is not None :
            self.start_time=start_time
            self.end_time=end_time
            self.time_range='CUSTOM'
        else :
            self.time_range=time_range

        self.load_async=load_async

    @property
    def time_range(self):
        """
        Query time range. See `msiempy.FilteredQueryList.POSSIBLE_TIME_RANGE`.
        Default to `msiempy.FilteredQueryList.DEFAULT_TIME_RANGE` (CURRENT_DAY).
        Note that the time range is upper cased automatically.
        Raises `VallueError` if unrecognized time range is set and `AttributeError` if not the right type.
        """
        return self._time_range.upper()

    @time_range.setter
    def time_range(self, time_range):
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
            raise AttributeError('time_range must be a string or None')

    @property
    def start_time(self):
        """
        Start time of the query in the right SIEM format.  
        Use `_start_time` to get the datetime object. You can set the `star_time` as a `str` or a `datetime`.  
        If `None`, equivalent CURRENT_DAY start 00:00:00. Raises `ValueError` if not the right type.  
        """
        return format_esm_time(self._start_time)

    @start_time.setter
    def start_time(self, start_time):
        if isinstance(start_time, str):
            self.start_time = convert_to_time_obj(start_time)
        elif isinstance(start_time, datetime.datetime):
            self._start_time = start_time
        elif start_time==None:
             self._start_time=None#raise ValueError("Time must be string or datetime object, not None")#self.start_time = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            raise ValueError("Time must be string or datetime object.")

    @property
    def end_time(self):
        """
        End time of the query in the right SIEM format.  
        Use `_end_time` property to get the datetime object. You can set the `end_time` as a `str` or a `datetime`.  
        If `None`, equivalent CURRENT_DAY. Raises `ValueError` if not the right type.
        """
        return format_esm_time(self._end_time)

    @end_time.setter
    def end_time(self, end_time):       
        if isinstance(end_time, str):
            self.end_time = convert_to_time_obj(end_time)
        elif isinstance(end_time, datetime.datetime):
            self._end_time = end_time
        elif end_time==None:
             self._end_time=None#raise ValueError("Time must be string or datetime object, not None")
        else:
            raise ValueError("Time must be string or datetime object.")

    @abc.abstractproperty
    def filters(self):
        """ 
        Filter property : Returns a list of filters.
        Can be set with list of tuple(field, [values]) or `msiempy.event.QueryFilter` in the case of a `msiempy.event.EventManager` query. A single tuple is also accepted.  
        `None value will call `msiempy.query.FilteredQueryList.clear_filters()`.  
        Raises : `AttributeError` if type not supported.
        TODO find a better solution to integrate the filter propertie
        """
        raise NotImplementedError()

    @filters.setter
    def filters(self, filters):
        if isinstance(filters, list):
            for f in filters :
                self.add_filter(f)

        elif isinstance(filters, tuple):
            self.add_filter(filters)

        elif filters == None :
            self.clear_filters()
        
        else :
            raise AttributeError("Illegal type for the filter object, it must be a list, a tuple or None.")

    
    @abc.abstractmethod
    def add_filter(self, filter):
        """Add a filter to the query.  
        Abstract declaration.
        """
        pass

    @abc.abstractmethod
    def clear_filters(self):
        """Remove all filters to the query.  
        Abstract declaration.
        """
        pass 

    @abc.abstractmethod
    def qry_load_data(self, *args, **kwargs):
        """
        Method to load the data from the SIEM.  
        Rturn a tuple (items, completed).  
        completed = True if all the data that should be load is loaded.  
        Abstract declaration.
        """
        pass

    @abc.abstractmethod
    def load_data(self, *args, **kwargs):
        """Load the data from the SIEM into the manager list.  
        Abstract declaration."""
        pass

