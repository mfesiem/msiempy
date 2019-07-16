### McAfee SIEM API Python wrapper
[![Build Status](https://travis-ci.org/mfesiem/msiempy.svg?branch=master)](https://travis-ci.org/mfesiem/msiempy)

This project aims to provide a basic API wrapper around the McAfee SIEM API to help make it more 
accessible and pythonic. 

### API Documentation
https://mfesiem.github.io/docs/msiempy/index.html

### Installation 
```
git clone https://github.com/mfesiem/msiempy
./setup.py install
```

### Configuration setup
```
$ python3
>>> from msiempy.config import NitroConfig
>>> config=NitroConfig()
>>> config.iset('esm')
Enter [esm]host. Press <Enter> to keep empty: <type here>
Enter [esm]user. Press <Enter> to keep empty: <type here>
Enter [esm]passwd. Press <Enter> to skip: <type here>
>>> config.iset('general')
Enter [general]verbose. Press <Enter> to keep no: 
Enter [general]quiet. Press <Enter> to keep False: 
Enter [general]logfile. Press <Enter> to keep empty: 
Enter [general]timeout. Press <Enter> to keep 60: 
Enter [general]ssl_verify. Press <Enter> to keep no: 
Enter [general]output. Press <Enter> to keep text:
>>> print(config)

        # The configuration file should be located securely in your path since it 
        # has credentials.
        # For Windows:  %APPDATA%\\.msiem/conf.ini
        # For Mac :     $HOME/.msiem/conf.ini
        # For Linux :   $XDG_CONFIG_HOME/.msiem/conf.ini
        #        or :   $HOME/.msiem/conf.ini
        # Use command line to setup authentication
        
Configuration file : /Users/username/.msiem/conf.ini
{'esm': {'host': '***', 'user': '***', 'passwd': '***=='}, 'general': {'verbose': 'no', 'quiet': 'False', 'logfile': '', 'timeout': '60', 'ssl_verify': 'no', 'output': 'text'}}
>>>config.write()
```

### Run tests
```
./setup.py test
[...]
----------------------------------------------------------------------
Ran 13 tests in 182.815s

OK
```
It souldn't take more than 5 minutes

#### Disclaimer
This is an **UNOFFICIAL** project and is **NOT** sponsored or supported by **McAfee, Inc**. If you accidentally delete all of your datasources, don't call support (or me). Product access will always be limited to 'safe' methods and with respect to McAfee's intellectual property.
