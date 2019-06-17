import configparser
import os
import getpass
import logging
log = logging.getLogger('msiempy')

from .utils import tob64

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

    DEFAULT_VERBOSE=False
    DEFAULT_LOGFILE=''
    DEFAULT_TIMEOUT=30
    DEFAULT_SSL_VERIFY=False
    DEFAULT_OUTPUT='text'

    DEFAULT_MAX_WORKERS=10
    DEFAULT_MAX_ROWS=200000
    DEFAULT_DEFAULT_ROWS=500
    DEFAULT_ASYNC_RULE='delta'
    DEFAULT_SLOTS=5
    DEFAULT_DELTA='5h'
    DEFAULT_MAX_QUERY_DEPTH=1

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
            
            'slots':DEFAULT_SLOTS,
            
            'max_query_depth':DEFAULT_MAX_QUERY_DEPTH}}

    def __str__(self):
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
    def max_query_depth(self):
        """
        Wether to split the query based on a time, a delta, or a fixed 
        number of slots in order to run them asynchronously
        """
        return self.getint('performance', 'max_query_depth')

    @property
    def slots(self):
        return self.getint('performance', 'slots')

   
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

