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


class FilteredQueryList(NitroList):
    """
    Abstract base class that provide time range handling and define the query filters.

    Base class for query based managers : `AlarmManager`, `EventManager` and `GroupedEventManager`
    
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
        """
        Create a query list

        Arguments:
            - `time_range` (`str`): Query time range. String representation of a time range.
                See `msiempy.core.query.FilteredQueryList.POSSIBLE_TIME_RANGE`.
            - `start_time` (`str` or a `datetime`): Query start time.
            - `end_time` (`str` or a `datetime`): Query end time.
            - `filters`: List of filters applied to the query.

        """ 

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
        """
        Boolean signals the query is not completed
        """

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
    """Default time range : ``"CURRENT_DAY"``"""

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
    """
    List of possible time ranges : 
        ``"CUSTOM"``,
        ``"LAST_MINUTE"``,
        ``"LAST_10_MINUTES"``,
        ``"LAST_30_MINUTES"``,
        ``"LAST_HOUR"``,
        ``"CURRENT_DAY"``,
        ``"PREVIOUS_DAY"``,
        ``"LAST_24_HOURS"``,
        ``"LAST_2_DAYS"``,
        ``"LAST_3_DAYS"``,
        ``"CURRENT_WEEK"``,
        ``"PREVIOUS_WEEK"``,
        ``"CURRENT_MONTH"``,
        ``"PREVIOUS_MONTH"``,
        ``"CURRENT_QUARTER"``,
        ``"PREVIOUS_QUARTER"``,
        ``"CURRENT_YEAR"``,
        ``"PREVIOUS_YEAR"``,
    """

    def _get_time_range(self):
        return self._time_range.upper()
    def _set_time_range(self, time_range):
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
    time_range = property(fget=_get_time_range, fset=_set_time_range)
    """
    Query time range. Defaults to ``"CURRENT_DAY"``.  
    
    Note:
        The time range is upper cased automatically.
    
    Raises: 
        `VallueError` if unrecognized time range is set or `AttributeError` if not the right type.
    """
    
    def _get_start_time(self):
        return format_esm_time(self._start_time)
    def _set_start_time(self, start_time):
        if isinstance(start_time, str):
            self.start_time = convert_to_time_obj(start_time)
        elif isinstance(start_time, datetime.datetime):
            self._start_time = start_time
        elif start_time == None:
            self._start_time = None
        else:
            raise ValueError("Time must be string or datetime object.")
    start_time = property(fget=_get_start_time, fset=_set_start_time)
    """
    Start time of the query in the right SIEM format.

    Use `_start_time` to get the datetime object.
    If `None`, equivalent ``CURRENT_DAY``.
    
    Raises:
        `ValueError` if not the right type.
    """

    def _get_end_time(self):
        return format_esm_time(self._end_time)

    def _set_end_time(self, end_time):
        if isinstance(end_time, str):
            self.end_time = convert_to_time_obj(end_time)
        elif isinstance(end_time, datetime.datetime):
            self._end_time = end_time
        elif end_time == None:
            self._end_time = None
        else:
            raise ValueError("Time must be string or datetime object.")
    
    end_time = property(fget=_get_end_time, fset=_set_end_time)
    """
    End time of the query in the right SIEM format.

    Use `_end_time` property to get the datetime object.
    If `None`, equivalent to ``CURRENT_DAY``.

    Raises:
        `ValueError` if not the right type.
    """

    def _get_filters(self):
        return self._get_filters()
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
    filters = property(fget=_get_filters, fset=_set_filters)
    """
    Query filters

    Note:
        `None` value will call `clear_filters`

    Raises:
        `AttributeError` if type not supported.

    Abstract declaration.
    """

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
