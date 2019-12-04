from msiempy import NitroConfig
from msiempy.__utils__ import tob64
import argparse

parser = argparse.ArgumentParser(description="""Setup authentication""")
parser.add_argument('--host', metavar='ESM address')    
parser.add_argument('--user', metavar='username')
parser.add_argument('--passwd', metavar='passwd')
args= parser.parse_args()

config=NitroConfig()

if args.host and args.user and args.passwd : 
    config.set('esm','host', args.host)
    config.set('esm', 'user', args.user)
    config.set('esm', 'passwd', tob64(args.passwd))
else :
    config.iset('esm')

config.write()