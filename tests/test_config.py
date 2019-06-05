import unittest
import msiempy.config

class T(unittest.TestCase):

    def test(self):

        config = msiempy.config.NitroConfig()
        
        print('setting [esm]*')
        config.iset('esm')
        config.write()

        print('printing config')
        print(config)


