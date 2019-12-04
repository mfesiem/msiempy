from msiempy.__version__ import __version__
from msiempy import NitroSession
session=NitroSession()
print('msiempy verison: {}'.format(__version__))
print('ESM version: {}'.format(session.request('build_stamp')['buildStamp']))