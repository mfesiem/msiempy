import msiempy.watchlist
import unittest


class T(unittest.TestCase):


    def test_print(self):
        watchlist_manager = msiempy.watchlist.WatchlistManager()
        print(watchlist_manager)

        #watchlist_manager=msiempy.watchlist.WatchlistManager(alist=watchlist_manager[:5])
        watchlist_manager.load_details()
        print(watchlist_manager)

        watchlist=msiempy.watchlist.Watchlist(id=3)
        print(watchlist)

        watchlist.load_values()

    def test_add_value(self):
        watchlist_manager = msiempy.watchlist.WatchlistManager()
        if len(watchlist_manager.search('TEST-msiempy'))>0:
            print(watchlist_manager)
            watchlist_manager.search('TEST-msiempy')[0].add_values(['test :)'])
        else :
            self.fail("No TEST-msiempy watchlist found, please create one.")
            pass
