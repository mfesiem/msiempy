import msiempy.watchlist
import unittest


class T(unittest.TestCase):


    def test_print(self):
        watchlist_manager = msiempy.watchlist.WatchlistManager()
        print(watchlist_manager)

        msiempy.watchlist.WatchlistManager(alist=watchlist_manager[:5]).load_details()
        print(watchlist_manager)

        watchlist=msiempy.watchlist.Watchlist(id=3)
        print(watchlist)

        watchlist.load_values()
        print(watchlist)
