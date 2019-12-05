from msiempy import NitroConfig
from msiempy.__utils__ import tob64
import argparse
"""
Usage example:  

    $ python ./samples/msiempy_setup.py --set esm host 207.179.200.58:4443 --set esm user NGCP --set esm passwd ${{ secrets.esmpass }} --set general verbose true --set general logfile ./log.txt --set general timeout 60


    $ python ./samples/msiempy_setup.py  
    Enter [esm]host. Press <Enter> to keep empty: <type here>  
    Enter [esm]user. Press <Enter> to keep empty: <type here>  
    Enter [esm]passwd. Press <Enter> to skip: <type here>  

"""

parser = argparse.ArgumentParser(description="""Setup msiempy configuration.""")
parser.add_argument('--set', '-s', metavar="'<section>' '<option>' '<value>'", action='append', nargs='+', help="""List of <section> <option> <value> to set.""", default=[])
args= parser.parse_args()

config=NitroConfig()
print(args)

if len(args.set)>0:
    for setting in args.set:
        if setting[1] == 'passwd':
            setting[2]=tob64(setting[2])
        config.set(setting[0], setting[1], setting[2])
else :
    config.iset('esm')

config.write()