from msiempy import NitroConfig
from msiempy.__utils__ import tob64
import argparse
"""
Usage example:  
 1. 
    $ python samples/msiempy_setup.py  
    Enter [esm]host. Press <Enter> to keep empty: <type here>   
    Enter [esm]user. Press <Enter> to keep empty: <type here>  
    Enter [esm]passwd. Press <Enter> to skip: <type here>  
 2. You can pass all config values as a list of (( <section> <option> <value> )) to the --set argument repetitively. 
    $ python samples/msiempy_setup.py --set esm host 207.179.200.58:4443 --set esm user NGCP --set esm passwd 'myp@assw0rd'  
    $ python samples/msiempy_setup.py --set general verbose true --set general logfile ./log.txt --set general timeout 60  
"""

parser = argparse.ArgumentParser(description="""Setup msiempy configuration.""")
parser.add_argument('--set', '-s', metavar="'<section>' '<option>' '<value>'", action='append', nargs='+', help="""List of <section> <option> <value> to set.""", default=[])
args= parser.parse_args()

config=NitroConfig()

if len(args.set)>0:
    for setting in args.set:
        if setting[1] == 'passwd':
            setting[2]=tob64(setting[2])
        config.set(setting[0], setting[1], setting[2])
else :
    config.iset('esm')

config.write()
