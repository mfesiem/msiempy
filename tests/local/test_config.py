import unittest
import msiempy


class T(unittest.TestCase):
    def test(self):

        config = msiempy.NitroConfig()

        print("setting [esm]*")
        # config.iset('esm')
        config.write()
