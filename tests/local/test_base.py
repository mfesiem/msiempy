import unittest
import pytest
import msiempy
import csv
import time
import json
import requests

def download_testing_data():
        """
        Terrestrial Climate Change Resilience - ACE [ds2738]

        California Department of Natural Resources — For more information, 
        see the Terrestrial Climate Change Resilience Factsheet 
        at http://nrm.dfg.ca.gov/FileHandler.ashx?DocumentID=150836.
        
        The California Department...
        """
        url='http://data-cdfw.opendata.arcgis.com/datasets/7c55dd27cb6b4f739091edfb1c681e70_0.csv'

        with requests.Session() as s:
            download = s.get(url)
            content = download.content.decode('utf-8')
            data = list(csv.DictReader(content.splitlines(), delimiter=','))
            return data

class T(unittest.TestCase):

    manager = msiempy.NitroList(alist=download_testing_data())

    def test_json(self):

        json_dump = T.manager.json
        try :
            loaded = json.loads(json_dump)
            self.assertEqual(len(T.manager), len(loaded), "Json dump doesn't have the same lengh as manger object")
            for i in range(len(loaded)):
                self.assertEqual(dict(T.manager[i]), loaded[i], "Json dump doesn't present the same info in the same order")
        except Exception as e:
            self.fail("Can't load json object :"+str(e))

    def test_item(self):
        pass

    def test_manager(self):
        sublist = msiempy.NitroList(alist=[item for item in T.manager if item['CLIM_RANK']=='1']) #.search('CLIM_RANK.*0','Eco_Name.*north')#.search('County.*GLENN') #len = 52
        
        # sublist.perform(self.test_add_money_money, progress=True, asynch=True, workers=500)
        # for item in sublist :
        #     self.assertRegex(item['CLIM_RANK'], '1|2', "Perform method issue ")
        
        # sublist.perform(self.test_add_money_money, progress=True, asynch=True, func_args=dict(how_much=2), workers=500)
        # for item in sublist :
        #     self.assertRegex(item['pct_hex'], '2|3|4', "Perform method issue ")

        # mycouty=sublist.search('County.*GLENN')
        # self.assertGreater(len(mycouty), 0, 'Search method issue')

        # mycouty.perform(self.test_add_money_money, progress=True, asynch=True, func_args=dict(how_much=500), workers=500)
        # for item in mycouty :
        #     self.assertRegex(item['pct_hex'], '502|503|504', "Perform method issue ")

    def test_print(self):
        data=download_testing_data()
        manager = msiempy.NitroList(alist=data[:30])
        manager[10]['County']=msiempy.NitroList(alist=data[:5])
        manager[20]['County']=data[:5]

        print('CSV')
        print(manager.get_text(format='csv'))

        print('NORMAL')
        print(manager.text)

        print('SPECIFIC FIELDS')
        print(manager.get_text(fields=['County', 'Eco_Name']))
    




