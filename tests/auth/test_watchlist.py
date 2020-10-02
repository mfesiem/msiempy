from msiempy import WatchlistManager, Watchlist
import unittest
from random import randint
import time


class T(unittest.TestCase):
    def test_print(self):
        watchlist_manager = WatchlistManager()
        print(watchlist_manager)

        # watchlist_manager=msiempy.watchlist.WatchlistManager(alist=watchlist_manager[:5])
        watchlist_manager.load_details()
        print(watchlist_manager)

        watchlist = Watchlist(id=3)
        print(watchlist)

        watchlist.load_values()

    def test_add_remove_value(self):
        watchlist_manager = WatchlistManager()
        # The test whatchlist contains IPs
        if len(watchlist_manager.search("TEST-msiempy")) > 0:

            print(watchlist_manager)
            ip = "{}.{}.{}.{}".format(
                randint(1, 253), randint(1, 253), randint(1, 253), randint(1, 253)
            )
            test_wl = watchlist_manager.search("TEST-msiempy")[0]
            test_wl.add_values([ip])
            time.sleep(2)
            test_wl.refresh()
            test_wl.load_values()

            self.assertIn(
                ip,
                test_wl["values"],
                "The test ip does not seem to have been added to wl",
            )

            test_wl.remove_values([ip])
            time.sleep(2)
            test_wl.refresh()
            test_wl.load_values()

            self.assertNotIn(
                ip,
                test_wl["values"],
                "The test ip does not seem to have been removed from wl",
            )

        else:
            self.fail("No TEST-msiempy watchlist found, please create one.")
            pass
