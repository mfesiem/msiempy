# -*- coding: utf-8 -*-
"""
Configuration parser object.  
"""
import logging
import configparser
import os
import getpass
from prettytable import MSWORD_FRIENDLY
from io import StringIO
from .utils import tob64

log = logging.getLogger("msiempy")

__pdoc__ = {}  # Init pdoc to document dynamically


class NitroConfig(configparser.ConfigParser):
    """

    Handles the configuration. Reads the config file `.msiem/conf.ini` where ever it is and make accessible it's values throught object properties.
    If a `.msiem/` directory exists in your current directory, the program will assume the `conf.ini` file is there, if not, it will create it with default values.
    Secondly, if no `.msiem/` directory exists in the current directory, it will be automatically placed in a appropriate place depending of your platform:

    Default configuration file should look like this. Authentication is left empty.
    ```
    [esm]
    host =
    user =
    passwd =

    [general]
    verbose = False
    quiet = False
    logfile =
    timeout = 60
    ssl_verify = False
    ```

    For Windows: `%APPDATA%\.msiem\conf.ini`
    For Mac : `$HOME/.msiem/conf.ini`
    For Linux : `$XDG_CONFIG_HOME/.msiem/conf.ini` or : `$HOME/.msiem/conf.ini`
    If `.msiem` folder exists in you local directory : `./.msiem/conf.ini`

    You can setup the configuration by command line with `msiempy_setup.py` script at https://github.com/mfesiem/msiempy/blob/master/samples/msiempy_setup.py .


    Arguments:

    - `path`: Config file special path, if path is left None, will automatically look for it.
    - `config`: Manual config dict. ex: `{'general':{'verbose':True}}`.
    - `*args, **kwargs` : Passed to `configparser.ConfigParser.__init__()` method.

    """

    def __init__(self, path=None, config=None, *arg, **kwarg):
        super().__init__(*arg, **kwarg)
        if not path:
            self._path = self.find_ini_location()
        else:
            self._path = path
        files = self.read(self._path)
        if len(files) == 0:
            log.info("Config file inexistant or currupted, applying defaults")
            self.read_dict(self.DEFAULT_CONF_DICT)
            if not os.path.exists(os.path.dirname(self._path)):
                os.makedirs(os.path.dirname(self._path))
            self.write()
        else:
            log.info("Successfuly read config file {}".format(files[0]))
        if config != None:
            log.info("Reading config_dict : " + str(self))
            self.read_dict(config)

    CONFIG_FILE_NAME = ".msiem/conf.ini"
    """`.msiem/conf.ini`"""

    CONF_DIR = ".msiem/"
    """`.msiem/`"""

    DEFAULT_CONF_DICT = {
        "esm": {"host": "", "user": "", "passwd": ""},
        "general": {
            "verbose": False,
            "quiet": False,
            "logfile": "",
            "timeout": 60,
            "ssl_verify": False,
        },
    }
    """
    Default configuration values.
    """

    def __str__(self):
        """
        Custom str() method that lists all config fields.
        """
        return (
            "Configuration file : "
            + self._path
            + "\n"
            + str({section: dict(self[section]) for section in self.sections()})
        )

    def write(self):
        """Write the config file to the predetermined path."""
        with open(self._path, "w") as conf:
            super().write(conf)
            log.info("Config file has been written at " + self._path)

    def _iset(self, section, option, secure=False):
        """Internal method to interactively set  a option in a section."""
        msg = "Enter [{}]{}"
        value = self.get(section, option)
        newvalue = ""
        if option == "passwd":
            secure = True
        if secure:
            newvalue = tob64(
                getpass.getpass(
                    msg.format(section, option) + ". Press <Enter> to skip: "
                )
            )
        else:
            newvalue = input(
                msg.format(section, option)
                + ". Press <Enter> to keep "
                + (value if (str(value) != "") else "empty")
                + ": "
            )
        if newvalue != "":
            super().set(section, option, newvalue)

    def iset(self, section, option=None, secure=False):
        """Interactively set the specified section/option by asking the user the input.
        Arguments:

        - `section`: Configuration's section. Exemple : 'esm' or 'general'.
        - `option`: Configuraion's option. Leave to `None` to set the whole section one after another. Exemple : 'user', 'timeout'.
        - `secure`: Will use getpass to retreive the configuration value and won't print old value.
        """
        if option is None:
            for key in self.options(section):
                self._iset(section, key, secure)
        else:
            self._iset(section, option, secure)

    @property
    def user(self):
        return self.get("esm", "user")

    @property
    def host(self):
        return self.get("esm", "host")

    @property
    def passwd(self):
        return self.get("esm", "passwd")

    @property
    def verbose(self):
        return self.getboolean("general", "verbose")

    @property
    def quiet(self):
        return self.getboolean("general", "quiet")

    @property
    def logfile(self):
        return self.get("general", "logfile")

    @property
    def timeout(self):
        return self.getint("general", "timeout")

    @property
    def ssl_verify(self):
        return self.getboolean("general", "ssl_verify")

    @staticmethod
    def find_ini_location():
        """
        Returns the location of a supposed conf.ini file the `conf.ini` file.
        If `.msiem` folder exists in you local directory, assume the `conf.ini` file is in there.
        If the file doesn't exist, will still return the location.
        Do not create a file nor directory, you must call `msiempy.core.config.NitroConfig.write`.
        """
        conf_path_dir = None
        if os.path.isdir("./" + NitroConfig.CONF_DIR):
            conf_path_dir = "./"
        elif "APPDATA" in os.environ:
            conf_path_dir = os.environ["APPDATA"]
        elif "XDG_CONFIG_HOME" in os.environ:
            conf_path_dir = os.environ["XDG_CONFIG_HOME"]
        elif "HOME" in os.environ:
            conf_path_dir = os.path.join(os.environ["HOME"])
        else:
            conf_path_dir = "./"
        # Join configuartion filename with supposed parent directory
        conf_path = os.path.join(conf_path_dir, NitroConfig.CONFIG_FILE_NAME)
        return conf_path
