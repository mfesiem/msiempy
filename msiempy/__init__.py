# -*- coding: utf-8 -*-
"""The point of convergence of every request to the McFee ESM It provides standard dialogue with the esm.
Configuration management, authentication, verbosity, logfile, general timeout, and others...
Two main type of classes are offered in this API : lists and dicts.
Managers are lists and Items are dicts.
"""
__version__ = '0.1.0'

import logging
import requests
import json
import ast
import re
import urllib.parse
import urllib3

from .params import PARAMS
from .utils import tob64

try :
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except : pass

logging.getLogger("urllib3").setLevel(logging.WARNING)
log = logging.getLogger('msiempy')

import configparser
import os
import getpass

import abc
import collections
import tqdm
import copy
import csv
import concurrent.futures
import prettytable
from prettytable import MSWORD_FRIENDLY
import datetime
import functools
import textwrap

from .utils import regex_match

class NitroError(Exception):
    """
    Base internal exception
    """
    pass

class NitroConfig(configparser.ConfigParser):
    """"NitroConfig
   Class that handles the configuration.
    """

    CONFIG_FILE_NAME='.msiem/conf.ini'
    CONF_DIR='.msiem/'

    CONFIG_FILE_DISCLAMER='''
        # The configuration file should be located securely in your path since it 
        # has credentials.
        # For Windows:  %APPDATA%\\\\'''+CONFIG_FILE_NAME+'''
        # For Mac :     $HOME/'''+CONFIG_FILE_NAME+'''
        # For Linux :   $XDG_CONFIG_HOME/'''+CONFIG_FILE_NAME+'''
        #        or :   $HOME/'''+CONFIG_FILE_NAME+'''
        # Use command line to setup authentication
        '''
    """
        # The configuration file should be located securely in your path since it 
        # has credentials.
        # For Windows:  %APPDATA%\\
        # For Mac :     $HOME/
        # For Linux :   $XDG_CONFIG_HOME/
        #        or :   $HOME/
        # Use command line to setup authentication
    """

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
    """
    Default configuration. Authentication is left empty.
    {
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
    """

    def __str__(self):
        """Custom str() method that lists all config fields.
        """
        return(self.CONFIG_FILE_DISCLAMER+'\nConfiguration file : '+
            self._path+'\n'+str({section: dict(self[section]) for section in self.sections()}))

    def __init__(self, path=None, config=None, *arg, **kwarg):
        """
        Initialize the Config instance.
        If path is left None, will automatically look for it.
        """

        super().__init__(*arg, **kwarg)

        self.read_dict(self.DEFAULT_CONF_DICT)
    
        if not path :
            self._path = self._find_ini_location()
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
        """
        Write the config file.
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
        """
        Will interactively set the specified section/optionby asking the user the input.
        If option stays None, all section's option will be interactively set.
        """
        if option is None :
            for key in self.options(section):
                self._iset(section, key, secure)
        else :
            self._iset(section, option, secure)

    @property
    def user(self):
        """ConfigParser.get('esm', 'user')"""
        return self.get('esm', 'user')

    @property
    def host(self):
        """ConfigParser.get('esm', 'host')"""
        return self.get('esm', 'host')

    @property
    def passwd(self):
        """ConfigParser.get('esm', 'passwd')"""
        return self.get('esm', 'passwd')

    @property
    def verbose(self):
        """ConfigParser.getboolean('general', 'verbose')"""
        return self.getboolean('general', 'verbose')

    @property
    def quiet(self):
        """ConfigParser.getboolean('general', 'quiet')"""
        return self.getboolean('general', 'quiet')

    @property
    def logfile(self):
        """ConfigParser.get('general', 'logfile')"""
        return self.get('general', 'logfile')

    @property
    def timeout(self):
        """ConfigParser.getint('general', 'timeout')"""
        return self.getint('general', 'timeout')

    @property
    def ssl_verify(self):
        """ConfigParser.getboolean('general', 'ssl_verify')"""
        return self.getboolean('general', 'ssl_verify')

    @property
    def output(self):
        """ConfigParser.get('general', 'output')"""
        return self.get('general', 'output')

   
    @staticmethod
    def _find_ini_location():
        '''
        Returns the location of a supposed conf.ini file the conf.ini file,
        If the file doesn't exist, will still return the location.
        Do not create a files not directory.
        If a .msiem/ directory exists in pwd, will return './.msiem/conf.ini'
        Or  For Windows:  %APPDATA%\\Roaming\\
            For Mac :     $HOME/
            For Linux :   $XDG_CONFIG_HOME/
                or :   $HOME/
        If your system doesn't have any of the above environment varibles,
            will return './.msiem/conf.ini'
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
    It provides standard dialogue with the esm with params.py
    Internal __dict__ refers to a unique instance of dict and thus, properties can be instanciated only once.
    No need to call a login() method. Credentials and other configurations are read from a ./.msiem/conf.ini file 
    If the ./msiem directory desn't exists in your current directory, will assume the file is your home directory
        as ~/.msiem/conf.ini or %appdata%\\Roaming\\.msiem\\conf.ini
    Use logout() to delete the object.
    Use NitroSession.config.read() - ConfigParser object - to read a new configuration file. 
    '''

    BASE_URL = 'https://{}/rs/esm/'
    """API v2 base url.
    """

    BASE_URL_PRIV = 'https://{}/ess/'
    """Private API base URL.
    """

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
    NitroConfig object.
    """
    
    executor = None
    """
    Executor object.
    """
        
    def __str__(self):
        """
    """
        return repr(self.__unique_state__) 

    def __init__(self, conf_path=None, conf_dict=None):
        """
        This init method is called every time you call NitroSession() constructor.
        but the properties are actually initiated only once.
        Use logout() to trash the obejct and re instanciate NitroSession.
        Configuration file path can be passed as conf_path attr and/or conf_dict.
        We read from conf_dict attr ie : {'esm':{'host':'myhost.com','user':'username','passwd':''}...}
            See NitroConfig class to have full details.
        """
        global log
        self.__dict__ = NitroSession.__unique_state__
        
        #Init properties only once
        if not self.__initiated__ :
            NitroSession.__initiated__ = True
            log.info('New NitroSession instance')
            
            #Private attributes
            self._headers={'Content-Type': 'application/json'}
            self._logged=False
            
            #Config parsing
            self.config = NitroConfig(path=conf_path, config=conf_dict)
            NitroSession.config=self.config

            #Set the logging configuration
            self._init_log(verbose=self.config.verbose,
                logfile=self.config.logfile)

    def _request(self, method, http, data=None, callback=None, raw=False, secure=False):
        """
        Helper method that format the request, handle the basic parsing of the SIEM result 
        as well as other errors.        
        If method is all upper cases, it's a private API call.
        Private API is under /ess/ and public api is under /rs/esm
        Returns None if HTTP error, Timeout or TooManyRedirects if raw=False
        """

        url=str()
        privateApiCall=False
        result=None

        #Handling private API calls formatting
        if method == method.upper():
            privateApiCall=True
            url = self.BASE_URL_PRIV
            data = self._format_params(method, **data)
            log.debug('Private API call : '+str(method)+' Formatted params : '+str(data))
        
        #Normal API calls
        else:
            url = self.BASE_URL
            if data:
                data = json.dumps(data)

        #Logging the data request if not secure | Logs anyway the method
        log.debug('Requesting HTTP '+http+' '+ method + 
            (' with data '+str(data) if (data is not None and not secure) else '') )

        try :
            result = requests.request(
                http,
                urllib.parse.urljoin(url.format(self.config.host), method),
                data=data, 
                headers=self._headers,
                verify=self.config.ssl_verify,
                timeout=self.config.timeout
            )

            if raw :
                log.debug('Returning raw requests Response object :'+str(result))
                return result

            else:
                try:
                    result.raise_for_status()

                except requests.HTTPError as e :
                    log.error(str(e)+' '+str(result.text))
                    return result.text
                    #TODO handle expired session error, result unavailable / other siem errors
                    # ERROR_InvalidFilter (228)
                    # Status Code 500: Error processing request, see server logs for more details 
                    # <Response [400]>
                    # Input Validation Error
                    # By creating a new class

                else: #
                    result = self._unpack_resp(result)

                    if privateApiCall :
                        result = self._format_priv_resp(result)

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
        
    def _login(self):
        """
        Internal method that will be called when the user is not logged yet.
        Throws NitroError if login fails
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
    
            return True
        else:
            raise NitroError('ESM Login Error: Response empty')

    def request(self, request, http='post', callback=None, raw=False, secure=False, **params):
        """
            This method is the centralized interface of all request coming to the SIEM.
                request :   keyword corresponding to the request name in PARAMS mapping
                http :      http method
                callback :  a callable to execute on the returned object if needed
                raw :       if true will return the Response object from requests module
                secure :    if true will not log the content of the request
                **params :  interpolation parameters that will be match to PARAMS templates

            Returns None if HTTP error, Timeout or TooManyRedirects if raw=False
            Should be stable.

        """
        log.debug("Calling nitro request : {} params={} http={} raw={} secure={} callback={}".format(
            str(request), str(params) if not secure else '***', str(http), str(raw), str(secure), str(callback)
        ))

        method, data = PARAMS.get(request)

        if data is not None :
            data =  data % params
            data = ast.literal_eval((data.replace('\n','').replace('\t','').replace("'",'"')))
           
        if method is not None:
            try :
                method = method % params
            except TypeError as err :
                if ('must be real number, not dict' in str(err)):
                    log.warning("Interpolation failed probably because of the private API calls formatting... Unexpected behaviours can happend.")

        if not self._logged and method != 'login':
            self._logged=self._login()

        try :
            return self._request(method, http, data, callback, raw, secure)

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
        NitroSession.__initiated__ = False

    @staticmethod
    def _init_log(verbose=False, logfile=None):
        """
        Private method. Inits the session's logger settings based on params
        All objects should be able to log stuff, so the logger is globaly accessible
        """

        log.setLevel(logging.DEBUG)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        std = logging.StreamHandler()
        std.setLevel(logging.DEBUG)
        std.setFormatter(formatter)

        if verbose :
            std.setLevel(logging.DEBUG)
        else :
            std.setLevel(logging.INFO)
            
        log.handlers=[]
        
        log.addHandler(std)

        if logfile :
            fh = logging.FileHandler(logfile)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            log.addHandler(fh)

        return (log)
    

    @staticmethod
    def _format_params(cmd, **params):
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
    def _format_priv_resp(resp):
        """
        Format response from private API
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
    def _unpack_resp(response) :
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
    Base class for all nitro objects. All objects have a reference the single
    NitroSession object that handle the esm requests.
    """

    class NitroJSONEncoder(json.JSONEncoder):
        """
        Custom JSON encoder that will use the approprtiate propertie depending of the type of NitroObject.
        TODO return meta info about the Manager. Maybe create a section `manager` and `data`.
        TODO support json json dumping of QueryFilers, may be by making them inherits from Item.
        """
        def default(self, obj): # pylint: disable=E0202
            if isinstance(obj,(Item, Manager)):
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
        """
        str(obj) -> return text string.
        Can be a table if the object is a Manager.
        """
        return self.text

    def __repr__(self):
        """
        repr(obj) -> return json string.
        """
        return self.json

    @abc.abstractproperty
    def text(self):
        """
        Returns printable string.
        """
        pass

    @abc.abstractproperty
    def json(self):
        """
        Returns json string representation.
        """
        pass

    @abc.abstractmethod
    def refresh(self):
        """
        Refresh the state of the object.
        """
        pass

class Item(collections.UserDict, NitroObject):
    """
    Base class that represent any SIEM data that can be represented as a item of a manager.
    Exemple : Event, Alarm, etc...
    Inherits from dict.
    """
    def __init__(self, adict=None, id=None):
        """
        Initiate the NitroObject and UserDict objects, load the data if id is specified, use adict agument 
        and update dict values accordingly.
        """
        NitroObject.__init__(self)
        collections.UserDict.__init__(self, adict)
        
        if id != None :
            self.data=self.data_from_id(id)

        if isinstance(adict, dict):
            self.data=adict

        for key in self.data :
            if isinstance(self.data[key], list):
                self.data[key]=Manager(alist=self.data[key])

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

class Manager(collections.UserList, NitroObject):
    """
    Base class for Managers objects. 
    Inherits from list
    """

    def __init__(self, alist=None):
        """
        Ignore nested lists. Meaning that if alist if a list of lists 
            it will we be ignored.
        Nevertheless, if a list is present as a key value in a dict, 
            it will be added as such.
        """
        NitroObject.__init__(self)
        if alist is None:
            collections.UserList.__init__(self, [])
        
        elif isinstance(alist , (list, Manager)):
            collections.UserList.__init__(
                self, alist #[Item(adict=item) for item in alist if isinstance(item, (dict, Item))] 
                #Can't instanciate Item, so Concrete classes has to cast the items afterwards
                )
        else :
            raise ValueError('Manager can only be initiated based on a list')

    @property
    def table_colums(self):
        """Return the list of columns the table representation will have. This attribute is designed to overwritten.
        """            
        return []

    def _norm_dicts(self):
        """
        Internal method
        all dict should have the same set of keys
        Creating keys in dicts
        """
        for item in self.data :
            if isinstance(item, (dict, Item)):
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
            if isinstance(item, (dict,Item)):
                manager_keys.update(item.keys())

        return manager_keys


    def get_text(self, compact=False, fields=None, max_column_width=120):
        """
        Return a acsii table string representation of the manager list
            compact : Returns a nice string table made with prettytable, else an '|' separated list.
            fields : list of fields you want in the table
                is None : default fields are returned by .keys attribute and sorted.
            max_column_width when using prettytable (not compact)

        It's an expesive thing to do on big ammount of data !
        """
        
        if not fields :
            fields=sorted(self.keys)

        if len(self) == 0 :
            return('The list is empty')

        if not compact : #Table
            table = prettytable.PrettyTable()
            table.set_style(MSWORD_FRIENDLY)
            table.field_names=fields
            self._norm_dicts()

            for item in self.data:
                if isinstance(item, (dict, Item)):
                    table.add_row(['\n'.join(textwrap.wrap(str(item[field]), width=max_column_width))
                        if not isinstance(item[field], Manager)
                        else item[field].get_text() for field in fields])
                else : log.warning("Unnapropriate list element type, doesn't show on the list : {}".format(str(item)))

            if len(self.table_colums) >0 :
                try :
                    text =table.get_string(fields=self.table_colums)
                except Exception as err :
                    if "Invalid field name" in str(err):
                        text=table.get_string()
                        log.warning("Inconsistent manager state, some fields aren't present {}".format(str(err)))
                    else :
                        raise
            else: 
                text=table.get_string()

        elif compact is True :
            text='|_'
            for field in fields :
                text+=field
                text+='_|_'
            text=text[0:len(text)-1]
            text+='\n'
            for item in self.data:
                if isinstance(item, (dict, Item)):
                    text+='| '
                    for field in fields :
                        if isinstance(item[field], Manager):
                            text+=item[field].get_text(compact=True)
                        else:
                            text+=(str(item[field]))
                            text+=' | '
                    text=text[0:len(text)-1]
                else : log.warning("Unnapropriate list element type, doesn't show on the list : {}".format(str(item)))
                    #text+=textwrap.wrap(str(item),width=max_column_width)
                text+='\n'
            text=text[0:len(text)-1]
        return text



    @property
    def text(self):
        """The text properti is a shorcut to get_text() with no arguments.
        """
        return self.get_text()
        
    @property
    def json(self):
        """Dumps a JSON list of dicts.
        """
        return(json.dumps([dict(item) for item in self.data], indent=4, cls=NitroObject.NitroJSONEncoder))

    def search(self, *pattern, invert=False, match_prop='json'):
        """
        Return a list of elements that matches regex patterns.
        Patterns are applied one after another. It's a logic AND.
        Use `|` inside patterns to search with logic OR.
        This method will return a new Manager with matching data. Items in the returned Manager do not
        references the items in the original Manager.

        If you wish to apply more specific filters to Manager list, please
        use filter(), list comprehension, or other filtering method.
            i.e. : `[item for item in manager if item['cost'] > 50]`

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
                if regex_match(apattern, getattr(item, match_prop) if isinstance(item, Item) else str(item)) is not invert :
                    matching_items.append(item)
            log.debug("You're search returned {} rows : {}".format(
                len(matching_items),
                str(matching_items)[:100]+'...'))
            #Apply AND reccursively
            return Manager(alist=matching_items).search(*pattern, invert=invert, match_prop=match_prop)
        else:
            raise ValueError('pattern must be str')

    def refresh(self):
        """
        Execute refresh function on all items.
        """
        log.warning("The function Manager.refresh hasn't been correctly tested")
        self.perform(Item.refresh)

    def perform(self, func, data=None, func_args=None, confirm=False, asynch=False,  workers=None , progress=False, message=None):
        """
        Wrapper arround executable and the data list of Manager object.
        Will execute the callable the local manager data list.

            Params
            
            func : callable stateless function
                funs is going to be called like func(item, **func_args) on all items in data patern
            if data stays None, will perform the action on all rows, else it will perfom the action on the data list
            func_args : dict that will be passed by default to func in all calls
            confirm : will ask interactively confirmation 
            asynch : execute the task asynchronously with NitroSession executor
            workers : mandatory if asynch is true
            progress : to show progress bar with ETA (tqdm) 
            message : To show to the user

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

        

        #Runs the callable on list on executor or by iterating
        if asynch == True :
            if isinstance(workers, int) :
                if progress==True:
                    #Need to call tqdm to have better support for concurrent futures executor
                    # tqdm would load the whole bar intantaneously and not wait until the callable func returns. 
                    returned=list(tqdm.tqdm(concurrent.futures.ThreadPoolExecutor(
                    max_workers=workers ).map(
                        func, elements), **tqdm_args))
                else:
                    #log.info()
                    returned=list(concurrent.futures.ThreadPoolExecutor(
                    max_workers=workers ).map(
                        func, elements))
            else:
                raise AttributeError('When asynch == True : You must specify a integer value for workers')
        else :

            if progress==True:
                elements=tqdm.tqdm(elements, **tqdm_args)

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