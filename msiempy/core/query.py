# -*- coding: utf-8 -*-
"""
Base query class with timerange handling.  
"""

from abc import abstractproperty
import logging
import abc
import datetime
from .utils import format_esm_time, convert_to_time_obj
from .types import NitroList

log = logging.getLogger("msiempy")

__pdoc__ = {}  # Init pdoc to document dynamically


class FilteredQueryList(NitroList):
    """
    Base class for query based managers : `msiempy.alarm.AlarmManager`, `msiempy.event.EventManager`.
    FilteredQueryList object can handle time_ranges and time splitting.
    Abstract base class that provide time ranged filtered query wrapper.

    Arguments:

    - `time_range` : Query time range. String representation of a time range.
        See `msiempy.core.query.FilteredQueryList.POSSIBLE_TIME_RANGE`.
    - `start_time` : Query starting time, can be a `string` or a `datetime` object. Parsed with `dateutil`.
    - `end_time` : Query endding time, can be a `string` or a `datetime` object. Parsed with `dateutil`.
    - `filters` : List of filters applied to the query.
    """

    def __init__(
        self,
        *arg,
        time_range=None,
        start_time=None,
        end_time=None,
        filters=None,
        **kwargs
    ):

        # Handled eventual deprecated arguments
        if "max_query_depth" in kwargs:
            log.warning(
                "Deprecated : `max_query_depth` argument has been removed from the object declaration for more clarty, it's now a specilized EventManager.load_data() argument only. This argument will be ignored."
            )
            del kwargs["max_query_depth"]
        if "requests_size" in kwargs:
            log.warning(
                "Deprecated : `requests_size` argument has been removed from FilteredQueryList, use `page_size` for AlarmManager or `limit` for EventManager arguments."
            )
            del kwargs["requests_size"]
        if "load_async" in kwargs:
            log.warning(
                "Deprecated : `load_async` argument has been removed from FilteredQueryList. Queries are now always loaded asynchronously."
            )
            del kwargs["load_async"]

        super().__init__(*arg, **kwargs)

        self.not_completed = False

        # Declaring attributes and types
        self._time_range = str()
        self._start_time = None
        self._end_time = None

        self.filters = filters  # filter property setter

        if start_time != None and end_time != None:
            self.start_time = start_time
            self.end_time = end_time
            self.time_range = "CUSTOM"
        else:
            self.time_range = time_range

    DEFAULT_TIME_RANGE = "CURRENT_DAY"
    __pdoc__[
        "FilteredQueryList.DEFAULT_TIME_RANGE"
    ] = """Default time range : %(default)s""" % dict(default=DEFAULT_TIME_RANGE)

    POSSIBLE_TIME_RANGE = [
        "CUSTOM",
        "LAST_MINUTE",
        "LAST_10_MINUTES",
        "LAST_30_MINUTES",
        "LAST_HOUR",
        "CURRENT_DAY",
        "PREVIOUS_DAY",
        "LAST_24_HOURS",
        "LAST_2_DAYS",
        "LAST_3_DAYS",
        "CURRENT_WEEK",
        "PREVIOUS_WEEK",
        "CURRENT_MONTH",
        "PREVIOUS_MONTH",
        "CURRENT_QUARTER",
        "PREVIOUS_QUARTER",
        "CURRENT_YEAR",
        "PREVIOUS_YEAR",
    ]
    __pdoc__[
        "FilteredQueryList.POSSIBLE_TIME_RANGE"
    ] = """
    List of possible time ranges : `%(timeranges)s`""" % dict(
        timeranges=", ".join(POSSIBLE_TIME_RANGE)
    )

    @property
    def time_range(self):
        """
        Query time range. See `msiempy.core.query.FilteredQueryList.POSSIBLE_TIME_RANGE`.
        Default to `msiempy.core.query.FilteredQueryList.DEFAULT_TIME_RANGE` (CURRENT_DAY).
        Note that the time range is upper cased automatically.
        Raises `VallueError` if unrecognized time range is set and `AttributeError` if not the right type.
        """
        return self._time_range.upper()

    @time_range.setter
    def time_range(self, time_range):
        if not time_range:
            self.time_range = self.DEFAULT_TIME_RANGE

        elif isinstance(time_range, str):
            time_range = time_range.upper()
            if time_range in self.POSSIBLE_TIME_RANGE:
                if time_range != "CUSTOM":
                    self.start_time = None
                    self.end_time = None
                self._time_range = time_range
            else:
                raise ValueError(
                    "The time range must be in " + str(self.POSSIBLE_TIME_RANGE)
                )
        else:
            raise AttributeError("time_range must be a string or None")

    @property
    def start_time(self):
        """
        Start time of the query in the right SIEM format.
        Use `_start_time` to get the datetime object. You can set the `star_time` as a `str` or a `datetime`.
        If `None`, equivalent CURRENT_DAY start 00:00:00.
        Raises: `ValueError` if not the right type.
        """
        return format_esm_time(self._start_time)

    @start_time.setter
    def start_time(self, start_time):
        if isinstance(start_time, str):
            self.start_time = convert_to_time_obj(start_time)
        elif isinstance(start_time, datetime.datetime):
            self._start_time = start_time
        elif start_time == None:
            self._start_time = None
        else:
            raise ValueError("Time must be string or datetime object.")

    @property
    def end_time(self):
        """
        End time of the query in the right SIEM format.
        Use `_end_time` property to get the datetime object. You can set the `end_time` as a `str` or a `datetime`.
        If `None`, equivalent CURRENT_DAY.
        Raises `ValueError` if not the right type.
        """
        return format_esm_time(self._end_time)

    @end_time.setter
    def end_time(self, end_time):
        if isinstance(end_time, str):
            self.end_time = convert_to_time_obj(end_time)
        elif isinstance(end_time, datetime.datetime):
            self._end_time = end_time
        elif end_time == None:
            self._end_time = None
        else:
            raise ValueError("Time must be string or datetime object.")

    @property
    def filters(self):
        """
        Filter property : Returns a list of filters.
        Can be set with list of tuple(field, [values]), a `msiempy.event.FieldFilter` or `msiempy.event.GroupFilter` in the case of a `msiempy.event.EventManager` query. A single tuple is also accepted.
        Filters will always be added to the list, use `clear_filters()` to remove all filters from a query.
        Raises : `AttributeError` if type not supported.
        Abstract declaration.
        """
        return self._get_filters()

    @filters.setter
    def filters(self, filters):
        self._set_filters(filters)

    def _set_filters(self, filters):
        if isinstance(filters, list):
            for f in filters:
                self.add_filter(f)

        elif isinstance(filters, tuple):
            self.add_filter(filters)

        elif filters == None:
            self.clear_filters()

        else:
            raise AttributeError(
                "Illegal type for the filter object, it must be a list, a tuple or None."
            )

    @abc.abstractmethod
    def _get_filters(self):
        """
        Returns the filters in the right format.
        Abstract declaration.
        """
        pass

    @abc.abstractmethod
    def add_filter(self, filter):
        """Add a filter to the query.
        Abstract declaration.
        """
        pass

    @abc.abstractmethod
    def clear_filters(self):
        """Remove all filters to the query.
        Abstract declaration.
        """
        pass

    @abc.abstractmethod
    def qry_load_data(self, *args, **kwargs):
        """
        Method to load the data from the SIEM.
        Rturns a `tuple ((items, completed))`.
        Abstract declaration.
        """
        pass

    @abc.abstractmethod
    def load_data(self, *args, **kwargs):
        """Load the data from the SIEM into the list.
        Abstract declaration."""
        pass
