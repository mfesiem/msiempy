import unittest
import msiempy.session

class T(unittest.TestCase):

    def test(self):
        
        esm=msiempy.session.NitroSession()

        esm.config.iset('esm')
        esm.config.write()

        print(esm.request('get_devtree'))
        print(esm.config)
        print(esm)

