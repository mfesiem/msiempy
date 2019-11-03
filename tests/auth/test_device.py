import time
import msiempy
from msiempy.device import ESM, DevTree, DataSource
import unittest

unittest.TestLoader.sortTestMethodsUsing = None

class T(unittest.TestCase):

    def test_esm(self):
       
        esm = ESM()

        print(str(esm.status()) + '\n' + str(esm.buildstamp()) + '\n' + str(esm.recs()))

    def setUp(self):
        print('Refreshing Devtree()')
        self.devtree = DevTree()

    def test_devtree1_has_devices(self):
        print('1. Testing that devtree has some devices...')
        self.assertGreater(len(self.devtree), 0)
    
    def test_devtree2_esm_at_top(self):
        print('2. Make sure there is an ESM at the top...')
        print(self.devtree[0]['name'])
        self.assertIn('ESM', self.devtree[0]['name'])

    def test_devtree3_datasource_cast(self):
        print('3. Make sure datasources are casted as DataSources...')
        for ds in self.devtree:
            if ds['desc_id'] == '3':
                datasource = self.devtree[ds['idx']]
                self.assertTrue(type(datasource) is msiempy.device.DataSource)
                print('DataSource Type Matches:', type(datasource) is msiempy.device.DataSource)
                continue
                
    def test_devtree4_check_old_test_datasource(self):
        print('4. Checking for old test datasource...')
        for ds in self.devtree:
            if ds['name'] == 'msiempy_test_datasource_delete_me':
                print('Old test datasource found. Deleting...')
                ds = self.devtree[ds['idx']]
                ds.delete()
                continue

    def test_devtree5_add_datasource(self):
        ds_config = {}
        for ds in self.devtree:
            if ds['desc_id'] in ['2', '13']:
                ds_config['parent_id'] = ds['ds_id']
            
        ds_config['name'] = 'msiempy_test_datasource_delete_me'
        ds_config['ds_ip'] = '0.20.5.5'
        ds_config['type_id'] = '65'
        print('5. Adding datasource...')
        print('Result ID: ', self.devtree.add(ds_config))
        print('Sleeping for 15 seconds before refresh...')
        time.sleep(15)

    def test_devtree6_load_ds_details(self):
        print('6. Loading DataSource details...')
        for ds in self.devtree:
            if ds['name'] == 'msiempy_test_datasource_delete_me':
                ds = self.devtree[ds['idx']]
                ds.load_details()
                print('DETAILS: {}'.format(ds.json))

    def test_devtree7_del_datasource(self):
         print('7. Deleting Datasource...')
         for ds in self.devtree:
            if ds['name'] == 'msiempy_test_datasource_delete_me':
                 print('Test datasource found. Deleting...')
                 ds = self.devtree[ds['idx']]
                 ds.delete()
                 continue

    def test_devtree8_verify_deleted(self):
         print('8. Verifying the datasource is gone...')
         for ds in self.devtree:
             self.assertNotEqual(ds['name'], 'msiempy_test_datasource_delete_me')

