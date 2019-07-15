import logging
import requests
import json
import ast
import re

import urllib.parse

import urllib3

from .error import NitroError
from .params import PARAMS
from .utils import tob64
from .config import NitroConfig

urllib3.disable_warnings()
logging.getLogger("urllib3").setLevel(logging.WARNING)

log = logging.getLogger('msiempy')

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
    BASE_URL_PRIV = 'https://{}/ess'

    __initiated__ = False
    __unique_state__ = {}
    
    config = None
    executor = None
        
    def __str__(self):
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
            if data :
                data = self._format_params(method, **data)
        
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

        if data :
            data =  data % params
            data = ast.literal_eval((data.replace('\n','').replace('\t','').replace("'",'"')))
           
        
        if method :
            method = method % params

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
