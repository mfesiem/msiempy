import unittest
import msiempy

class T(unittest.TestCase):

    def test(self):

        session=msiempy.NitroSession()
        
        session.logout()
        session.login()
        
        tz=session.request('time_zones')
        for t in tz :
            if not 'offset' in t:
                self.fail("Timezone object from the SIEM doesn't represent a offset attribute")

