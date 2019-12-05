from msiempy import NitroConfig
from msiempy.__utils__ import tob64
import argparse

parser = argparse.ArgumentParser(description="""Setup msiempy configuration""")
parser.add_argument('--set', '-s', metavar="'<section>' '<option>' '<value>'", action='append', nargs='+', help="""List of <section> <option> <value> to set.""", default=[])
args= parser.parse_args()

config=NitroConfig()
print(args)

if len(args.set)>0:
    for setting in args.set:
        config.set(setting[0], setting[1], setting[2])
else :
    config.iset('esm')

config.write()