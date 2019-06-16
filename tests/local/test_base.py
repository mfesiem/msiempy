import unittest
import msiempy.base
import csv
import time
import requests
from msiempy.base import Item

class T(unittest.TestCase):

    def test(self):
        
        print('creating new items')
        items = [
            {'first':'John', 'last':'Lennon','born':1940,'role':'guitar'},
            {'first':'Paul', 'last':'McCartney','born':1942,'role':'bass'},
            {'first':'George','last':'Harrison','born':1943,'role':'guitar'},
            {'first':'Ringo','last':'Starr','born':1940,'role':'drums'},
            {'first':'George','last':'Martin','born':1926,'role':'producer', 'extra':'producer', 
            'a_list':[
                {'first':'user1', 'last':'non','born':1950,'role':'guitar'},
                {'first':'user2', 'last':'neyney','born':2042,'role':'basser'},
                {'first':'user3','last':'heris','born':1999,'role':'bloom'},
                {'first':'user55','last':'was','born':1946,'role':'core'},
                {'first':'me','last':'nono','born':1726,'role':'dancer', 'extra':'producer', 
            }
            ]}
        ]

        print('printing items')
        print(items)

        print('creating manager')
        manager=msiempy.base.Manager(items)

        print('printing text of manager[0]')
        print(manager[0].text)

        print('printing json of manager[0]')
        print(str(manager[0].json))

        print('printing text of manager')
        print(manager.text)

        print('printing json of manager')
        print(manager.json)

        print('printing repr of manager')
        print(repr(manager))

        print('search result manager')
        print(manager.search('George').text)

        print(manager.perform(repr, '2042', confirm=True, asynch=False, search_args=dict(invert=True)))

    def test_json(self):
        pass

    def test_item(self):
        pass

    def test_manager(self):
        manager = msiempy.base.Manager(alist=msiempy.base.Manager.download_testing_data())
        sublist = manager.search('CLIM_RANK.*0','Eco_Name.*north')#.search('County.*GLENN') #len = 52
        print(sublist.text)
        print(sublist.perform(T.test_add_money_money, progress=True, asynch=True))
        print(sublist.text)
        print(sublist.perform(T.test_add_money_money, progress=True, asynch=True))
        print(sublist.text)
        print(sublist.perform(T.test_add_money_money,
            progress=True,
            asynch=True,
            func_args=dict(how_much=5)))

        print(sublist.text)

        mycouty=sublist.search('County.*GLENN')
        mycouty.perform(
            T.test_add_money_money,
            confirm=True,
            progress=True,
            asynch=True,
            func_args=dict(how_much=500))

        
        print(mycouty.text)
        print(sublist.text)

    @staticmethod
    def test_add_money_money(item, how_much=1):
        item['pct_hex']=str(int(item['pct_hex'])+how_much)
        
        time.sleep(0.1)

        return (int(item['\ufeffOBJECTID'])-int(item['pct_hex']))