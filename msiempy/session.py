"""Session package regroup method and classes that are shared by all msiempy objects.
NitroSession class
NitroConfig class
"""

import logging
import requests
import json
import ast
import re
import os
import urllib.parse
import getpass
import concurrent.futures
import configparser
import urllib3

from .error import NitroError
from .utils import tob64
from .params import PARAMS

urllib3.disable_warnings()
logging.getLogger("urllib3").setLevel(logging.WARNING)

class NitroSession():
    """NitroSession object represent the point of convergence of every request to the McFee ESM
    It provides standard dialogue with the esm with params.py
    Internal __dict__ refers to a unique instance of dict and thus, properties can be instanciated only once.
    No need to call a login() method
    Use logout() to delete the object.
    """

    BASE_URL = 'https://{}/rs/esm/'
    BASE_URL_PRIV = 'https://{}/ess'

    __initiated__ = False
    __unique_state__ = {}

    log = None
    config = None
    executor = None

    @staticmethod
    def _init_log(verbose=False, logfile=None) -> object:
        """
        Private method. Inits the session's logger based on params
        #TODO not too sure where to put the logger init method, 
        All objects should be able to log stuff, NitroConig too, so the logger must be globaly accessible
        """
        
        log = logging.getLogger('msiempy')
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
            fh.setLevel(logging.INFO)
            fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            log.addHandler(fh)
        
        
        return (log)
        
    def __str__(self):
        return repr(self.__unique_state__) 

    def __init__(self, conf_path=None, config=None):
        """
        This init method is called every time you call NitroSession() constructor
        but teh properties are actually initiated only once.
        Use logout() to trash the obejct and re instanciate NitroSession
        Configuration file path can be passed as conf_path attr and a config dict
        can we read from config attr ie {'esm':{'host':'myhost.com','user':'username','passwd':'p22ssw0rd'}}
        """
        self.__dict__ = NitroSession.__unique_state__
        
        #Init properties only once
        if not self.__initiated__ :
            NitroSession.__initiated__ = True

            self.log = self._init_log()
            NitroSession.log=self.log

            self.log.info('New NitroSession instance')
            
            #Private attributes
            self._headers={'Content-Type': 'application/json'}
            self._logged=False
            
            #Config parsing
            self.config = NitroConfig(path=conf_path, config=config)
            NitroSession.config=self.config

            self.log = self._init_log(
                verbose=self.config.verbose,
                logfile=self.config.logfile )
            NitroSession.log=self.log
            
            self.executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.max_workers )
            NitroSession.executor=self.executor

    def _request(self, method, http, data=None, callback=None, raw=False, secure=False) -> object:
        """
        Helper method that format the request, handle the basic parsing of the SIEM result 
        as well as other errors.        
        If method is all upper cases, it's a private API call.
        Private API is under /ess/ and public api is under /rs/esm
        """

        url=str()
        privateApiCall=False
        result=None

        #Handling private API calls formatting
        if method == method.upper():
            privateApiCall=True
            url = self.BASE_URL_PRIV
            if data :
                data = self._format_params(method, **data)
        
        #Normal API calls
        else:
            url = self.BASE_URL
            if data:
                data = json.dumps(data)

        #Logging the data request if not secure | Logs anyway the method
        self.log.debug('Requesting '+http+' '+ method + ((' with data '+str(data) if data is not None else '') if not secure else ''))

        try :
            result = requests.request(
                http,
                urllib.parse.urljoin(url.format(self.config.host), method),
                data=data, 
                headers=self._headers,
                verify=self.config.ssl_verify,
                timeout=self.config.timeout
            )

            if not secure :
                pass
                #self._logger.debug('RESULT : '+result.text)
                #Uncomment to log the data returned ** Very noisy

            if raw :
                return result

            else:
                try:
                    result.raise_for_status()

                except requests.HTTPError as e :
                    self.log.error(str(e)+' '+str(result.text))
                    #TODO handle expired session error, result unavailable / other siem errors

                else: #
                    try:
                        result = self._unpack_resp(result)

                    except json.decoder.JSONDecodeError:
                        result = result.text

                    if privateApiCall :
                        result = self._format_priv_resp(result)

                    if callback:
                        result = callback(result)

                    return result

        except ConnectionError as e:
            self.log.critical(e)
            raise
        except requests.exceptions.Timeout as e:
            self.log.error(e)
            pass
        except requests.exceptions.TooManyRedirects as e :
            self.log.error(e)
            pass
        except Exception as e:
            self.log.error(e)
        
    def _login(self):
        """
        Internal method that will be called when the user is not logged yet.
        Throws NitroError if login fails
        """
        userb64 = tob64(self.config.user)
        passb64 = self.config.passwd
        
        resp = self.request('login', username=userb64, password=passb64, raw=True, secure=True)
        
        if resp:
            if resp.status_code in [400, 401]:
                raise NitroError('Invalid username or password for the ESM')
            elif 402 <= resp.status_code <= 600:
                raise NitroError('ESM Login Error:', resp.text)
       
            self._headers['Cookie'] = resp.headers.get('Set-Cookie')
            self._headers['X-Xsrf-Token'] = resp.headers.get('Xsrf-Token')
    
            return True

    def request(self, request, http='post', callback=None, raw=False, secure=False, *args, **params) -> object:
        """
            This method is the centralized interface of all request coming to the SIEM.
                request :   keyword corresponding to the request name in PARAMS mapping
                http :      http method
                callback :  a callable to execute on the returned object if needed
                raw :       if true will return the Response object from requests module
                secure :    if true will not log the content of the request
                *args :     supplementary attributes (TBD)
                **params :  interpolation parameters that will be match to PARAMS template

        """
        log_param = locals()
        del log_param['self']
        if  secure :
            del log_param['params']
        self.log.debug("Calling request with params :"+str(log_param))

        method, data = PARAMS.get(request)

        if data :
            data =  data % params
            data = ast.literal_eval(''.join(data.split()))
        
        if method :
            method = method % params

        post=dict()

        if not self._logged and method != 'login':
            self._logged=self._login()

        try :
            post = self._request(method, http, data, callback, raw, secure)
            return post

        except Exception as err:
            self.log.error(str(err))
            raise err
        
    def logout(self):
        """ 
        This method will logout the session, clear headers and throw away the object,
         a new session will be instanciated next time.
        """
        self.request('logout', http='delete')
        del self._headers
        NitroSession.__initiated__ = False
        NitroSession.__unique_state__ = {}

    @staticmethod
    def _format_params(cmd, **params) -> object:
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
    def _format_priv_resp(resp) -> object:
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
    def _unpack_resp(response) -> object:
        """Unpack data from response.
        Args: 
            response: requests response object
        """
        data = response.json()
        if isinstance(response.json(), dict):
            try:
                data = data['value']
            except KeyError:
                try:
                    data = data['return']
                except KeyError:
                    pass
        return data

    

class NitroConfig(configparser.ConfigParser):
    """"NitroConfig

    """


    CONFIG_FILE_NAME='.msiem/conf.ini'

    CONFIG_FILE_DISCLAMER='''
        # The configuration file should be located securely in your path since it 
        # has credentials.
        # For Windows:  %APPDATA%\\\\'''+CONFIG_FILE_NAME+'''
        # For Mac :     $HOME/'''+CONFIG_FILE_NAME+'''
        # For Linux :   $XDG_CONFIG_HOME/'''+CONFIG_FILE_NAME+'''
        #        or :   $HOME/'''+CONFIG_FILE_NAME+'''
        # Use command line to setup authentication
        '''

    DEFAULT_VERBOSE=False
    DEFAULT_LOGFILE=''
    DEFAULT_TIMEOUT=30
    DEFAULT_SSL_VERIFY=False
    DEFAULT_OUTPUT='text'

    DEFAULT_MAX_WORKERS=15
    DEFAULT_MAX_ROWS=200000
    DEFAULT_DEFAULT_ROWS=5000
    DEFAULT_ASYNC_RULE='slots'
    DEFAULT_ASYNC_SLOTS=5
    DEFAULT_ASYNC_DELTA='5mn'

    DEFAULT_CONF_DICT={'esm':{'host':'', 
            'user':'',
            'passwd':''},
        'general':{'verbose':DEFAULT_VERBOSE,
            'logfile':DEFAULT_LOGFILE,
            'timeout':DEFAULT_TIMEOUT,
            'ssl_verify':DEFAULT_SSL_VERIFY,
            'output':DEFAULT_OUTPUT},
        'performance':{'max_workers':DEFAULT_MAX_WORKERS,
            'max_rows':DEFAULT_MAX_ROWS,
            'default_rows':DEFAULT_DEFAULT_ROWS, 
            'async_rule':DEFAULT_ASYNC_RULE,
            'async_slots':DEFAULT_ASYNC_SLOTS,
            'async_delta':DEFAULT_ASYNC_DELTA}}

    def __str__(self):
        return(NitroConfig.CONFIG_FILE_DISCLAMER+'\nConfiguration file : '+
            self._path+'\n'+str({section: dict(self[section]) for section in self.sections()}))

    def __init__(self, path=None, config=None, *arg, **kwarg):
        """
        Initialize the Config instance.
        """

        super().__init__(*arg, **kwarg)

        self.read_dict(NitroConfig.DEFAULT_CONF_DICT)
    
        if not path :
            self._path = self._find_ini_location()
        else : 
            self._path = path

        try :
            files=self.read(self._path)
            if len(files) == 0:
                raise FileNotFoundError

        except :
            NitroSession.log.info("Config file inexistant or currupted, applying defaults")

            if not os.path.exists(os.path.dirname(self._path)):
                os.makedirs(os.path.dirname(self._path))
            self.write()

        if config is not None :
            NitroSession.log.info("Read! "+str(self))
            self.read_dict(config)

    def write(self):
        NitroSession.log.info("Write config file at "+self._path)
        with open(self._path, 'w') as conf:
            super().write(conf)
        

    def _iset(self, section, option, secure=False):
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
        if option is None :
            for key in self.options(section):
                self._iset(section, key, secure)
        else :
            self._iset(section, option, secure)

    @property
    def user(self):
        return self.get('esm', 'user')

    @property
    def host(self):
        return self.get('esm', 'host')

    @property
    def passwd(self):
        return self.get('esm', 'passwd')

    @property
    def verbose(self):
        return self.getboolean('general', 'verbose')

    @property
    def logfile(self):
        return self.get('general', 'logfile')

    @property
    def timeout(self):
        return self.getint('general', 'timeout')

    @property
    def ssl_verify(self):
        return self.getboolean('general', 'ssl_verify')

    @property
    def output(self):
        return self.get('general', 'output')

    @property
    def max_workers(self):
        return self.getint('performance', 'max_workers')

    @property
    def max_rows(self):
        return self.getint('performance', 'max_rows')

    @property
    def default_rows(self):
        return self.getint('performance', 'default_rows')

    @property
    def async_rule(self):
        """
        Wether to split the query based on a time, a delta, or a fixed 
        number of slots in order to run them asynchronously
        """
        return self.get('performance', 'async_rule')

    @property
    def async_slots(self):
        return self.get('performance', 'async_slots')

    @property
    def async_delta(self):
        return self.get('performance', 'async_delta')

    @staticmethod
    def _find_ini_location() -> object:
        """
        Attempt to locate the conf.ini file 
        """
        conf_path=None

        if 'APPDATA' in os.environ:
            conf_path = os.environ['APPDATA']

        elif 'XDG_CONFIG_HOME' in os.environ:  
            conf_path = os.environ['XDG_CONFIG_HOME']

        elif 'HOME' in os.environ:  
            conf_path = os.path.join(os.environ['HOME'])
        
        else:
            conf_path='./'
    
        conf_path=(os.path.join(conf_path, NitroConfig.CONFIG_FILE_NAME))

        return(conf_path)

