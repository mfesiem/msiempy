# -*- coding: utf-8 -*-
"""A few quick static util methods.
"""

import base64
import re
from functools import wraps
from datetime import datetime, timedelta
import dateutil.parser

__pdoc__ = {}  # Init pdoc to document dynamically


def dehexify(data):
    """
    A URL and Hexadecimal Decoding Library.
    Credit: Larry Dewey. In the case of the SIEM API, this is used only when dealing with the pricate API calls.
    """

    hexen = {
        "\x1c": ",",  # Replacing Device Control 1 with a comma.
        "\x11": "\n",  # Replacing Device Control 2 with a new line.
        "\x12": " ",  # Space
        "\x22": '"',  # Double Quotes
        "\x23": "#",  # Number Symbol
        "\x27": "'",  # Single Quote
        "\x28": "(",  # Open Parenthesis
        "\x29": ")",  # Close Parenthesis
        "\x2b": "+",  # Plus Symbol
        "\x2d": "-",  # Hyphen Symbol
        "\x2e": ".",  # Period, dot, or full stop.
        "\x2f": "/",  # Forward Slash or divide symbol.
        "\x7c": "|",  # Vertical bar or pipe.
    }

    uri = {
        "%11": ",",  # Replacing Device Control 1 with a comma.
        "%12": "\n",  # Replacing Device Control 2 with a new line.
        "%20": " ",  # Space
        "%22": '"',  # Double Quotes
        "%23": "#",  # Number Symbol
        "%27": "'",  # Single Quote
        "%28": "(",  # Open Parenthesis
        "%29": ")",  # Close Parenthesis
        "%2B": "+",  # Plus Symbol
        "%2D": "-",  # Hyphen Symbol
        "%2E": ".",  # Period, dot, or full stop.
        "%2F": "/",  # Forward Slash or divide symbol.
        "%3A": ":",  # Colon
        "%7C": "|",  # Vertical bar or pipe.
    }

    for (enc, dec) in hexen.items():
        data = data.replace(enc, dec)

    for (enc, dec) in uri.items():
        data = data.replace(enc, dec)

    return data


# Unused method
# def timethis(func):
#     """
#     Decorator that reports the execution time.
#     """
#     @wraps(func)
#     def wrapper(*args, **kwargs):
#         """Wrapper"""
#         start = time.time()
#         result = func(*args, **kwargs)
#         end = time.time()
#         print(func.__name__, end-start)
#         return result
#     return wrapper


def tob64(s):
    """
    Encode a string to base64 almost like `echo '123' | base64` would do.
    """
    if type(s) is str:
        return base64.b64encode(s.encode("utf-8")).decode()


def fromb64(s):
    """
    Decode a string to base64 almost like `echo 'MTIzCg==' | base64 --decode` would do.
    """
    if type(s) is str:
        return base64.b64decode(s.encode("utf-8")).encode()


# Usefull to compte CURRENT_WEEK timerange
# one_day = timedelta(days=1)
# def get_week(date):
#     """
#     Return the full week (Sunday first) of the week containing the given date.

#         - 'date' may be a datetime or date instance (the same type is returned).
#     """
#     day_idx = (date.weekday() + 1) % 7  # turn sunday into 0, monday into 1, etc.
#     sunday = date - timedelta(days=day_idx)
#     date = sunday
#     for n in range(7):
#         yield date
#         date += one_day


def timerange_gettimes(time_range):
    """
    Convert a string time range to a tuple of datetime objects. Only works for certain time ranges.
    """
    t = time_range.upper()
    now = datetime.now()
    times = tuple()

    if t == "LAST_MINUTE":
        times = (now - timedelta(seconds=60), now)

    elif t == "LAST_10_MINUTES":
        times = (now - timedelta(minutes=10), now)

    elif t == "LAST_30_MINUTES":
        times = (now - timedelta(minutes=30), now)

    elif t == "LAST_HOUR":
        times = (now - timedelta(minutes=60), now)

    elif t == "CURRENT_DAY":
        times = (
            now.replace(hour=0, minute=0, second=0),
            now.replace(hour=23, minute=59, second=59),
        )

    elif t == "PREVIOUS_DAY":
        yesterday = now - timedelta(hours=24)
        times = (
            yesterday.replace(hour=0, minute=0, second=0),
            yesterday.replace(hour=23, minute=59, second=59),
        )

    elif t == "LAST_24_HOURS":
        times = (now - timedelta(hours=24), now)

    elif t == "LAST_2_DAYS":
        times = (now - timedelta(days=2), now)

    elif t == "LAST_3_DAYS":
        times = (now - timedelta(days=3), now)
    # TODO Support other time ranges
    # elif t == 'CURRENT_WEEK':
    #     pass
    # elif t == 'PREVIOUS_WEEK':
    #     pass
    # elif t == 'CURRENT_MONTH':
    #     pass
    # elif t == 'PREVIOUS_MONTH':
    #     pass
    # elif t == 'CURRENT_QUARTER':
    #     pass
    # elif t == 'PREVIOUS_QUARTER':
    #     pass
    # elif t == 'CURRENT_YEAR':
    #     pass
    # elif t == 'PREVIOUS_YEAR':
    #     pass
    else:
        raise NotImplementedError("Timerange " + t + " is not supported yet")

    return (times[0].isoformat(), times[1].isoformat())


def divide_times(first, last, slots=0, delta=0, time=0):
    """
    Divide the time range based on a delta or on a number of slots or another time,.
    Return list of tuple
    """

    # parse the dates
    t1 = convert_to_time_obj(first) if not isinstance(first, datetime) else first
    t2 = convert_to_time_obj(last) if not isinstance(last, datetime) else last

    duration = t2 - t1

    if slots == 0:
        if delta == 0:
            if time == 0:
                raise AttributeError("Either time, slots or delta must be specified")
            else:
                div = convert_to_time_obj(time) - t1

        elif isinstance(delta, timedelta):
            div = delta
        elif isinstance(delta, str):
            div = parse_timedelta(delta)
        else:
            raise AttributeError("delta Must be timedelta or str object")

        slots = int(duration.total_seconds() / div.total_seconds()) + 1

    timeSlot = timedelta(seconds=duration.total_seconds() / slots)

    # print(locals())

    times = list()

    for i in range(slots):
        times.append((t1, t1 + timeSlot))
        t1 += timeSlot

    return times


def regex_match(regex, string):
    """
    Return True if the string match the regex.
    """
    if re.search(regex, string):
        return True
    else:
        return False


def format_esm_time(esm_time):
    """Converts time object to ESM time string.

    Arguments:

    - `time_obj` (`datetime.datetime`)

    Returns: time string in format `2019-04-08T19:35:02.971Z`
    """
    _esm_out_time_fmt = "%m/%d/%Y %H:%M:%S"
    _esm_in_time_fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    if isinstance(esm_time, str):
        esm_time = convert_to_time_obj(esm_time)  # , _esm_out_time_fmt)
    return datetime.strftime(esm_time, _esm_in_time_fmt)


def convert_to_time_obj(time_str):
    """
    Converts given timestamp string to datetime object

    Args:
        time_str: timestamp in format 'YYYY/MM/DD HH:MM:SS',
                         'MM/DD/YYYY HH:MM:SS', or 'DD/MM/YYYY HH:MM:SS'

    Returns:
        datetime object or None if no format matches
    """
    return dateutil.parser.parse(time_str)


def parse_query_result(columns, rows):
    """
    For input :

        columns = [{'name': 'Alert.LastTime'}, {'name': 'Rule.msg'}, {'name': 'Alert.DstIP'}, {'name': 'Alert.IPSIDAlertID'}]
        rows =
            [
                {'values': ['09/22/2020 15:51:14', 'Postfix Disconnect from host', '::', '144116287604260864|547123']},
                {'values': ['09/22/2020 15:51:14', 'Postfix Lost connection from host', '::', '144116287604260864|547122']}
            }

    Returns :

        [
            {
                "Alert.LastTime":"09/22/2020 15:51:14",
                "Rule.msg":"Postfix Disconnect from host",
                "Alert.DstIP":"::",
                "Alert.IPSIDAlertID":"144116287604260864|547123"
            },
            {
                ...
            },
        ]

    """
    events = list()
    for row in rows:
        event = dict()
        for i in range(len(columns)):
            event.update({columns[i]["name"]: row["values"][i]})

        events.append(event)

    return events


def format_fields_for_query(fields):
    """
    Format fields names to cann query module.

    Arguments:

    - `fields`: list of fields, i.e. `['field1','name','user']`

    Returns:

        [
            {'name':'field1'},
            {'name':'name'},
            {'name':'user'},
        ]

    """
    return [{"name": value} for value in list(fields)]


def parse_timedelta(time_str):
    """
    Parse a time string e.g. (`2h13m`) into a timedelta object.

    Modified from virhilo's answer at https://stackoverflow.com/a/4628148/851699

    Arguments:

    - `time_str`: A string identifying a duration.  (eg. `2h13m`)


    Returns `datetime.timedelta`: A datetime.timedelta object
    """
    regex = re.compile(
        r"^((?P<days>[\.\d]+?)d)?((?P<hours>[\.\d]+?)h)?((?P<minutes>[\.\d]+?)m)?((?P<seconds>[\.\d]+?)s)?$"
    )
    parts = regex.match(time_str)
    assert (
        parts is not None
    ), "Could not parse any time information from '{}'.  Examples of valid strings: '8h', '2d8h5m20s', '2m4s'".format(
        time_str
    )
    time_params = {
        name: float(param) for name, param in parts.groupdict().items() if param
    }
    return timedelta(**time_params)


# Unused method
# def sanitize_string(strg, valid_chars = ''):
#     ''' Sanitize string
#         Usage:
#             By default returns the string without special characters, underscore replaced with space, and surrounding whitespace removed
#             :valid_chars: By default this function removes all characters. Specifying a string of characters here will skip removing them

#         Edited from https://github.com/AutomationSolutionz/Zeuz_Python_Node/blob/master/Framework/Built_In_Automation/Built_In_Utility/CrossPlatform/BuiltInUtilityFunction.py
#     '''

#     # Invalid character list (space and underscore are handle separately)
#     invalid_chars = '!"#$%&\'()*+,-./:;<=>?@[\]^`{|}~'

#     # Adjust invalid character list, based on function input
#     for j in range(len(valid_chars)): # For each valid character
#         invalid_chars = invalid_chars.replace(valid_chars[j], '') # Remove valid character from invalid character list

#     for j in range(0,len(invalid_chars)): # For each invalid character (allows us to only remove those the user hasn't deemed valid)
#         strg = strg.replace(invalid_chars[j], '') # Remove invalid character
#         strg = strg.lower() # Convert to lower case
#     if '_' not in valid_chars: strg = strg.replace('_', ' ') # Underscore to space (unless user wants to keep it)

#     strg = strg.replace('  ', ' ') # Double space to single space
#     strg = strg.strip() # Remove leading and trailing whitespace


#     return strg


def nitro_tz(tz_id):
    """Maps McAfee SIEM/Nitro ESM internal timezone IDs to
    the tz database at: http://web.cs.ucla.edu/~eggert/tz/tz-link.htm

    Args:
        tz_id (str/int): McAfee ESM internal timezone ID

    Returns:
        timezone name (str)

    """

    tz_map = {
        1: "Pacific/Pago_Pago",
        2: "Pacific/Honolulu",
        3: "America/Anchorage",
        4: "America/Los_Angeles",
        5: "America/Phoenix",
        6: "America/Chihuahua",
        7: "America/Denver",
        8: "America/Guatemala",
        9: "America/Chicago",
        10: "America/Mexico_City",
        11: "America/Regina",
        12: "America/Bogota",
        13: "America/New_York",
        14: "America/Indiana/Indianapolis",
        15: "America/Halifax",
        16: "America/Caracas",
        17: "America/Santiago",
        18: "America/St_Johns",
        19: "America/Sao_Paulo",
        20: "America/Buenos_Aires",
        21: "America/Godthab",
        22: "Atlantic/South_Georgia",
        23: "Atlantic/Azores",
        24: "Atlantic/Cape_Verde",
        25: "Africa/Casablanca",
        26: "Etc/UTC",
        27: "Europe/Amsterdam",
        28: "Europe/Belgrade",
        29: "Europe/Brussels",
        30: "Europe/Warsaw",
        31: "Africa/Tripoli",
        32: "Europe/Athens",
        33: "Europe/Bucharest",
        34: "Africa/Cairo",
        35: "Africa/Maputo",
        36: "Europe/Helsinki",
        37: "Asia/Jerusalem",
        38: "Asia/Baghdad",
        39: "Asia/Riyadh",
        40: "Europe/Moscow",
        41: "Africa/Nairobi",
        42: "Asia/Tehran",
        43: "Asia/Dubai",
        44: "Asia/Baku",
        45: "Asia/Kabul",
        46: "Asia/Yekaterinburg",
        47: "Asia/Karachi",
        48: "Asia/Kolkata",
        49: "Asia/Kathmandu",
        50: "Asia/Almaty",
        51: "Asia/Dhaka",
        52: "Asia/Colombo",
        53: "Asia/Rangoon",
        54: "Asia/Bangkok",
        55: "Asia/Krasnoyarsk",
        56: "Asia/Shanghai",
        57: "Asia/Irkutsk",
        58: "Asia/Singapore",
        59: "Australia/Perth",
        60: "Asia/Taipei",
        61: "Asia/Tokyo",
        62: "Asia/Seoul",
        63: "Asia/Yakutsk",
        64: "Australia/Adelaide",
        65: "Australia/Darwin",
        66: "Australia/Brisbane",
        67: "Australia/Sydney",
        68: "Pacific/Guam",
        69: "Australia/Hobart",
        70: "Asia/Vladivostok",
        71: "Asia/Magadan",
        72: "Pacific/Auckland",
        73: "Pacific/Fiji",
        74: "Pacific/Tongatapu",
        75: "Asia/Tbilisi",
        76: "Europe/Dublin",
        77: "Europe/Istanbul",
    }

    return tz_map[tz_id]
