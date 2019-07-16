import msiempy.device
import unittest


class T(unittest.TestCase):

    def test_devtree_to_lod_full(self, devtree_str):
        
        devtree_str = """14,Local ESM,144115188075855872,0,T,T,T,T,T,T,T,T,TTT,1,0,T,306,,F,F,F,TTT,,syslog,0,T,F,10.10.26.15,,3,1,
                     15,ACE-1,144120685633994752,0,T,T,T,T,T,T,T,T,FTT,0,0,F,TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT,10001000,ACE-VM4,F,F,TTT,,,0,T,F,10.10.26.16,,4,1,
                     17,Destination IP Risk,144120685667549184,3,T,T,T,T,T,T,T,T,TTT,6,0,T,345,,F,F,F,TTT,6,corr,0,T,F,10.10.26.16,,0,0,
                     3,Rule Correlation,144120685650771968,2,T,T,T,T,T,T,T,T,TTT,6,0,T,47,ace,F,F,F,TTT,0,corr,0,T,F,10.10.26.16,,0,0,
                     17,Source IP Risk,144120685684326400,4,T,T,T,T,T,T,T,T,TTT,6,0,T,345,,F,F,F,TTT,6,corr,0,T,F,10.10.26.16,,0,0,
                     17,Source User Risk,144120685701103616,5,T,T,T,T,T,T,T,T,TTT,6,0,T,345,,F,F,F,TTT,6,corr,0,T,F,10.10.26.16,,0,0,
                     25,ELS-1,144121785145622528,0,T,T,T,T,T,T,T,T,TTT,3,0,F,TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT,10000001,ELS-VM4,F,F,TTT,,syslog,0,T,F,10.10.22.66,,0,0,
                     2,ERC-1,144117387099111424,0,T,T,T,T,T,T,T,T,TTT,3,0,F,TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT,10001000,ERC-VM4,F,F,TTT,,syslog,0,T,F,10.10.26.17,,9,1,
                     3,app,144117387182997504,6,T,T,T,T,T,T,T,T,TTT,0,0,T,65,syslog,F,F,F,TTT,0,gsyslog,0,T,F,10.10.26.3,,0,0,
                     3,gw,144117387166220288,5,T,T,T,T,T,T,T,T,TTT,0,0,T,65,syslog,F,F,F,TTT,0,gsyslog,0,T,F,10.10.26.1,,0,0,
                     3,Mail,144117387199774720,7,T,T,T,T,T,T,T,T,TTT,0,0,T,65,syslog,F,F,F,TTT,0,gsyslog,0,T,F,10.10.26.4,,0,0,
                     3,monster,144117388458065920,80,T,T,T,T,T,T,T,T,TTT,6,0,T,43,wmi,F,F,F,TTT,0,wmi,0,T,F,10.10.22.50,,0,0,
                     3,NS0,144117387216551936,8,T,T,T,T,T,T,T,T,TTT,0,0,T,65,syslog,F,F,F,TTT,0,gsyslog,0,T,F,10.10.26.10,,0,0,
                     3,NS1,144117387233329152,9,T,T,T,T,T,T,T,T,TTT,0,0,T,65,syslog,F,F,F,TTT,0,gsyslog,0,T,F,10.10.26.12,,0,0,
                     3,Test-Parent-1,144117388424511488,78,T,T,T,T,T,T,T,T,TTT,6,0,T,65,syslog,F,F,F,TTT,6,gsyslog,0,T,F,12.0.0.0,,1,1,
                     254,1,144117388424511744|144117388424577024,0,F,F,F,F,F,F,F,F,TTT,,,F,,,F,F,F,TTT,,,0,F,F,12.0.0.0,,0,0,
                     3,Testbox,144117388441288704,79,T,T,T,T,T,T,T,T,TTT,6,0,T,166,syslog,F,F,F,TTT,0,gsyslog,0,T,F,10.10.23.17,,0,0,
                     3,Tool,144117387149443072,4,T,T,T,T,T,T,T,T,TTT,0,0,T,65,syslog,F,F,F,TTT,0,gsyslog,0,T,F,10.10.26.6,,0,0,"""


        testtree = msiempy.device.DevTree._devtree_to_lod(devtree_str)
        self.assertNotEqual(testtree['0']['enabled'], None)

    def test_print(self):
        devtree = msiempy.device.DevTree()
        print(devtree)
