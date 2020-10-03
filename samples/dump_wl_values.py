import argparse
from msiempy import WatchlistManager

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Dump ESM Watchlist values to a text file.  "
    )
    parser.add_argument("--wl", help="ESM Watchlist name")
    parser.add_argument("--list", "-l", action="store_true", help="List all Watchlists")
    parser.add_argument("--out", help="Output text file. Print only if none")
    args = parser.parse_args()
    all_watchlists = WatchlistManager()
    if args.list:
        print(
            all_watchlists.get_text(
                fields=["name", "type", "valueCount", "active", "source", "id"]
            )
        )
    if args.wl:
        my_wl = [w for w in all_watchlists if w["name"] == args.wl]
        if not len(my_wl):
            raise ValueError("Watchlist not found")
        else:
            my_wl = my_wl[0]
        my_wl.load_values()
        if args.out:
            with open(args.out, "w") as o:
                o.write("\n".join(my_wl["values"]))
        else:
            print("\n".join(my_wl["values"]))
