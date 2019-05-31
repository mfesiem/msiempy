import unittest
import msiempy.session

class T(unittest.TestCase):

    def test(self):
        
        print('creating new instance')
        esm=msiempy.session.NitroSession()

        print('setting [esm]*')
        esm.config.iset('esm')
        esm.config.write()

        print('getting devtree')
        print(esm.request('get_devtree'))

        print('printing config')
        print(esm.config)

        print('printing esm')
        print(esm)

