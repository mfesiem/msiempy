import unittest
import msiempy.base
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

        manager.perform(print, '2042', confirm=True, asynch=False, search=dict(invert=True))

        manager.refresh()

        print(manager.selected_items)
