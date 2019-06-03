import unittest
import msiempy.session

class T(unittest.TestCase):

    def test(self):
        
        print('creating new instance')
        session=msiempy.session.NitroSession()

        print('setting [esm]*')
        session.config.iset('esm')
        session.config.write()

        print('getting time_zones')
        print(session.request('time_zones'))

        print('printing config')
        print(session.config)

        print('printing session')
        print(session)

        session.logout()

        print(session)

        print('getting esm_time')
        print(session.request('get_esm_time')) #The error is normal cause we just logged out

