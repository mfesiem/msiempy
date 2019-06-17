import unittest
import msiempy.base
import csv
import time
import json
import requests
from msiempy.base import Item

def test_add_money_money(item, how_much=1):
    item['pct_hex']=str(int(item['pct_hex'])+how_much)
    time.sleep(0.02)
    return (int(item['\ufeffOBJECTID'])-int(item['pct_hex']))

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

    manager = msiempy.base.Manager(alist=download_testing_data())

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
        sublist = T.manager.search('CLIM_RANK.*0','Eco_Name.*north')#.search('County.*GLENN') #len = 52
        
        sublist.perform(test_add_money_money, progress=True, asynch=True)
        for item in sublist :
            self.assertEqual(item['pct_hex'], '1', "Perform method issue ")
        
        sublist.perform(test_add_money_money, progress=True, asynch=True, func_args=dict(how_much=2))
        for item in sublist :
            self.assertEqual(item['pct_hex'], '3', "Perform method issue ")

        mycouty=sublist.search('County.*GLENN')
        self.assertEqual(len(mycouty), 52, 'Search method issue')

        mycouty.perform(test_add_money_money, progress=True, asynch=True, func_args=dict(how_much=500))
        for item in mycouty :
            self.assertEqual(item['pct_hex'], '503', "Perform method issue ")


