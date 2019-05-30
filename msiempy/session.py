import logging
import concurrent.futures
import configparser

class NitroSession():
    """NitroSession object represent the point of convergence of every request to the McFee ESM

    It provides standard dialogue with the esm with params.py
    
    Internal __dict__ refers to a unique instance of dict and thus, properties can be instanciated only once
    """

    __initiated__ = False
    __unique_state__ = {}

    @staticmethod
    def _get_logger(verbose=False, logfile=None):

        log = logging.getLogger()
        log.setLevel(logging.DEBUG)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        std = logging.StreamHandler()
        std.setLevel(logging.DEBUG)
        std.setFormatter(formatter)

        if verbose :
            std.setLevel(logging.DEBUG)
        else :
            std.setLevel(logging.INFO)
            
        log.addHandler(std)

        if logfile :
            fh = logging.FileHandler(logfile)
            fh.setLevel(logging.INFO)
            fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            log.addHandler(fh)

        return (log)
        
    def __init__(self, conf_path=None, **config):
        self.__dict__ = self.__unique_state__
        
        #Init properties only once
        if not self.__initiated__ :
            self.__initiated__ = True
            
            #Private attributes
            self._headers={'Content-Type': 'application/json'}
            self._logged=False
            
            #Config parsing
            self.config = NitroConfig(path=conf_path, **config)
            
            self.executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.max_workers )

            self.log = self._get_logger(
                verbose=self.config.verbose,
                logfile=self.config.logfile )
    
    def _post(self, method, data, callback, etc) -> object:
        pass

    def _login(self, url, user, passwd):
        pass

    def request(self, request, *arg, **kwargs) -> object:
        """
        esm_request()
        """
        pass

    

class NitroConfig(configparser.ConfigParser):
    """"NitroConfig

    """
    def __init__(self, path=None, **kwconfig):
        """
        Initialize the Config instance.
        """
        super().__init__()

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
        return self.get('performance', 'max_workers')

    @property
    def max_rows(self):
        return self.get('performance', 'max_rows')

    @property
    def default_rows(self):
        return self.get('performance', 'default_rows')

