import unittest
import msiempy.session as siem

class T(unittest.TestCase):

    def test(self):
        
        esm=siem.NitroSession()
        print(esm.request('get_devtree'))
        print(esm.config)
        print(esm)
        
        pass


    pass