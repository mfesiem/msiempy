import msiempy.device
import unittest


class T(unittest.TestCase):

    def test_print(self):
        devtree = msiempy.device.DevTree()
        [print(dev.props()) for dev in devtree]

        esm = msiempy.device.ESM()

        print(str(esm.status()) + '\n' + str(esm.buildstamp()) + '\n' + str(esm.recs()))
