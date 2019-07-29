import msiempy.device
import unittest


class T(unittest.TestCase):

    def test_print(self):
        
        #DevTree() instanciation can be very long due to repetitive calls to the same enpoints.
        #Tests are skipped for now in order to focus on other priorities...
        
        #devtree = msiempy.device.DevTree()
        #[print(dev.props()) for dev in devtree]

        esm = msiempy.device.ESM()

        print(str(esm.status()) + '\n' + str(esm.buildstamp()) + '\n' + str(esm.recs()))
