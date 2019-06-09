from .utils import regex_match, convert_to_time_obj, divide_times
from .error import NitroError
from .session import NitroSession
import abc
import collections
import json
import tqdm
import copy
import prettytable
import datetime
import logging
log = logging.getLogger('msiempy')


class NitroObject(abc.ABC):
    """
    Base class for all nitro objects. All objects have a reference the single
    NitroSession object that handle the esm requests
    """

    class NitroJSONEncoder(json.JSONEncoder):
        def default(self, obj):  # pylint: disable=E0202
            if isinstance(obj, (Item, Manager)):
                return obj.data
            else:
                return json.JSONEncoder.default(self, obj)

    @abc.abstractmethod
    def __init__(self):
        """
        self.nitro.request('esm-get-times')
        """
        self.nitro = NitroSession()

    def __str__(self):
        return self.text

    @abc.abstractproperty
    def text(self):
        """
        Returns str
        """
        pass

    @abc.abstractproperty
    def json(self):
        """
        Returns json repr
        """
        pass

    @abc.abstractmethod
    def refresh(self):
        """
        Refresh the state of the object
        """
        pass

    @staticmethod
    def action_refresh(ntiro_object):
        """
        Refrech callable to use with perform()
        """
        return(ntiro_object.refresh())


class Item(collections.UserDict, NitroObject):
    """
    Base class that represent any SIEM data that can be
    represented as a item of a manager.

    Exemple : Event, Alarm, etc...
    Inherits from dict
    """

    def __init__(self, other_dict=None):
        NitroObject.__init__(self)
        collections.UserDict.__init__(self, other_dict)

        for key in self.data:
            if isinstance(self.data[key], list):
                self.data[key] = Manager(self.data[key])

        self.selected = False

    @property
    def json(self):
        return(json.dumps(dict(self), indent=4, cls=NitroObject.NitroJSONEncoder))

    @property
    def text(self):
        return(repr(dict(self)))

    def refresh(self):
        log.debug('Refreshing '+str(self))

    '''This code has been commented cause it adds unecessary complexity.
    But it's a good example of how we could perform() method to do anything

    def select(self):
        self.selected=False

    def unselect(self):
        self.selected=True

    @staticmethod
    def action_select(item):
        item.select()

    @staticmethod
    def action_unselect(item):
        item.unselect()'''


class Manager(collections.UserList, NitroObject):
    """
    Base class for Managers objects.
    Inherits from list
    """

    SELECTED = 'b8c0a7c5b307eeee30039343e6f23e9e4f1d325bbc2ffaf1c2b7b583af160124'
    """
    Random constant represents all selected items to avoid regex matching interference.
    """

    def __init__(self, other_list=None):
        """
        Ignore nested lists. Meaning that if other_list if a list of lists
            it will we be ignored
        Nevertheless, if a list is present as a key valur in a dict,
            it will be added as such
        """
        NitroObject.__init__(self)
        if other_list is None:
            other_list = []
        if isinstance(other_list, list):
            collections.UserList.__init__(
                self, [Item(item) for item in other_list if isinstance(item, (dict, Item))])
        else:
            raise ValueError('Manager can only be initiated based on a list')

    @property
    def text(self):
        table = prettytable.PrettyTable()
        fields = set()

        for item in self.data:
            fields = fields.union(dict(item).keys())

        fields = sorted(fields)
        table.field_names = fields

        for item in self.data:
            if isinstance(item, NitroObject):
                for key in fields:
                    if key not in item:
                        item[key] = '-'
                table.add_row([str(item[field]) for field in fields])

        return table.get_string()

    @property
    def json(self):
        return json.dumps([dict(item) for item in self.data],
                          indent=4, cls=NitroObject.NitroJSONEncoder)

    def search(self, pattern=None, invert=False, match_func='json'):
        """
        Return a list of elements that matches regex pattern
        See https://docs.python.org/3/library/re.html#re.Pattern.search
        """
        if isinstance(pattern, str):
            try:
                matching_items = list()
                for item in self.data:
                    if regex_match(pattern, getattr(item, match_func)) is not invert:
                        matching_items.append(item)
                return Manager(matching_items)

            except Exception as err:
                raise NotImplementedError(str(err))
        elif pattern is None:
            return self
        else:
            raise ValueError('pattern must be str or None')

    ''' This code has been commented cause it adds unecessary complexity.
    But it's a good example of how we could perform() method to do anything

    def select(self, data_or_pattern, **search):
        """
        Select the rows that match the pattern.
        The patterm could be a index, list of index or list of rows
        """
        self.perform(Item.action_select, data_or_pattern, **search)

    def unselect(self, data_or_pattern, **search):
        """
        Unselect the rows that match the pattern.
        The patterm could be a index, list of index or list of rows
        """
        self.perform(Item.action_unselect, data_or_pattern, **search)
        '''

    def clear(self):
        for item in self.data:
            item.selected = False
        # self.perform(Item.action_unselect, '.*') :

    def refresh(self):
        self.perform(Item.action_refresh, '.*')

    def perform(self, func, pattern=None, search=None, *args, **kwargs):
        """
            func : callable stateless function
            if data_or_pattern stays None, will perform the action on
            the selected rows. If no rows are selected, it will perform
            on all rows.

            Pattern can be:
                - string regex pattern match using search
                - a child Item object
                - a Manager(list) of Item(dict)
                - a list of lists of dict
                    However, only list of dict can be passed if asynch=True
                - Manager.SELECTED
            search: dict passed as extra **arguments to search method
                i.e :
                    {invert=False, match_func='json'} or
                    {time_range='CUSTOM', start_time='2019', end_time='2020'}
            confirm : will ask interactively confirmation
            asynch : execute the task asynchronously with NitroSession executor
            progress : to show progress bar with ETA (tqdm)

        Returns a list of returned results
        """
        # if confirm : self.__ask(func, data_or_pattern)
        # If pattern is left None, apply the action to selected rows
        # if any else everything Recursion +1
        if pattern is None:
            return self.__perform(func,
                                  self, *args, **kwargs)

        # pattern is a string
        if isinstance(pattern, str):

            # Selected items only
            # +1 Recursion
            if pattern == self.SELECTED:
                return self.__perform(func,
                                      self.selected_items,
                                      *args, **kwargs)
            else:
                # Regex search when pattern is String.
                # search method returns a list
                # +1 Recursion
                return self.__perform(
                    func,
                    self.search(
                        pattern, **(search if search is not None else {})),
                    *args, **kwargs)

        # If passed other object type
        #   use static __perform directly
        return self.__perform(func,
                              datalist=pattern,
                              *args, **kwargs)

    @staticmethod
    def __ask(func, data):
        if 'y' not in input('Are you sure you want to do this '+str(func)+' on ' +
                            ('\n'+str(data) if data is not None else 'all')+'? [y/n]: '):
            raise InterruptedError

    @staticmethod
    def __perform(func, datalist, confirm=False, asynch=False, progress=False, _recursions_=1):
        """
        Static helper perform method
        """
        log.debug('Calling perform func='+str(func) +
                  ' with pattern :'+str(datalist))

        if not callable(func):
            raise ValueError('func must be callable')

        if not isinstance(datalist, (list, dict, Manager, Item)):
            raise ValueError(
                'datalist can only be : (list, dict, Manager, Item) not '+str(type(datalist)))

        if confirm:
            Manager.__ask(func, datalist)

        returned = list()

        # End of the recursion potential
        _recursions_ -= 1
        if _recursions_ < 0:
            log.warning(RecursionError('''maximum perform recursion reached :/
                try a data structure more simple. recursions=1 implies that
                only list of dicts are supported.
                Increase recursions argument to support list of lists'''))
            return returned

        # A list of data is passed to perform()
        #   this includes the possibility of being a Manager object
        # +1 Recursion if iterative mode (default)
        # +0 Recursion if asynch : use executor
        if isinstance(datalist, (Manager, list)):

            if progress is True:
                datalist = tqdm.tqdm(datalist)

            if asynch is True:

                # Throws error if recursive asynchronous jobs are requested
                if any([not isinstance(data, (dict, Item)) for data in datalist]):
                    raise ValueError('''recursive asynchronous jobs are not supported.
                        datalist list can only contains dict or Item obects if asynch=True''')

                else:
                    returned = list(NitroSession().executor.map(
                        func,
                        datalist))
            else:
                for index_or_item in datalist:
                    returned.append(Manager.__perform(
                        func,
                        index_or_item,
                        _recursions_=_recursions_))

            return(returned)

        # The acual object last Recusion +0
        elif isinstance(datalist, (dict, Item)):
            return(func(datalist))

    @property
    def selected_items(self):
        return(Manager([item for item in self.data if item.selected]))


class QueryManager(Manager):
    """
    Base class for query based managers. QueryManager object can handle time_ranges.
    """
    DEFAULT_TIME_RANGE = "CURRENT_DAY"
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
        "PREVIOUS_YEAR"
    ]

    def __init__(self, time_range=None, start_time=None, end_time=None, filters=None,
                 sub_query=1, *arg, **kwargs):
        """
        Base class that handles the time ranges operations, loading data from the SIEM
        """

        super().__init__(*arg, **kwargs)

        self.nitro.config.default_rows  # nb rows per request : eq limit/page_size
        self.nitro.config.max_rows

        # Declaring attributes and types
        self._time_range = str()
        self._start_time = None
        self._end_time = None

        self.filters = filters
        self.sub_query = sub_query

    @property
    def time_range(self):
        return self._time_range

    @property
    def start_time(self):
        return self._start_time

    @property
    def end_time(self):
        return self._end_time

    @time_range.setter
    def time_range(self, time_range):
        """
        Set the time range of the query to the specified string value. Defaulf POSSIBLE_TIME_RANGE
        """

        if not time_range:
            self._time_range = self.DEFAULT_TIME_RANGE

        elif isinstance(time_range, str):
            time_range = time_range.upper()
            if time_range in self.POSSIBLE_TIME_RANGE:
                self._time_range = time_range
            else:
                raise NitroError("The time range must be in " +
                                 str(self.POSSIBLE_TIME_RANGE))
        else:
            raise ValueError('time_range must be a string or None')

    @start_time.setter
    def start_time(self, start_time):
        """
        Set the time start of the query.
        """

        if not start_time:
            self.start_time = datetime.datetime.now().replace(
                hour=0, minute=0, second=0, microsecond=0)
        elif isinstance(start_time, str):
            self.start_time = convert_to_time_obj(start_time)
        elif isinstance(start_time, datetime.datetime):
            self._start_time = start_time
        else:
            raise ValueError("Time must be string or datetime object.")

    @end_time.setter
    def end_time(self, end_time):
        """
        Set the time end of the query.
        """

        if not end_time:
            self.end_time = datetime.datetime.now()
        elif isinstance(end_time, str):
            self.end_time = convert_to_time_obj(end_time)
        elif isinstance(end_time, datetime.datetime):
            self._end_time = end_time
        else:
            raise ValueError("Time must be string or datetime object.")

    @abc.abstractproperty
    def filters(self):
        pass

    @filters.setter
    def filters(self, filters):

        if isinstance(filters, list):
            for f in filters:
                self.add_filter(f)

        elif isinstance(filters, tuple):
            self.add_filter(filters)

        elif filters is None:
            self.clear_filters()

        else:
            raise NitroError(
                "Illegal type for the filter object, it must be a list, a tuple or None.")

    @abc.abstractmethod
    def add_filter(self, filter):
        pass

    @abc.abstractmethod
    def clear_filters(self):
        pass

    @abc.abstractmethod
    def _load_data(self):
        """
        Must return a tuple (items, completed)
        conmpleted = True if all the data that should be load is loaded
        """
        pass

    @staticmethod
    def action_load_data(querymanager):
        return(querymanager.load_data())

    @abc.abstractmethod
    def load_data(self):
        """
        Method to load data from the SIEM.

        Split the query in defferents time slots if the query apprears not to be completed.

        Splitting is done by duplicating current object, setting different times,
        and re-loading results.
        Use async_slots in config file to control how many queries to use.
        Only async_slots configuration fields is taken into account for now.

        Returns a QueryManager.
        """

        items, completed = self._load_data()

        if not completed:
            # If not completed the query is split and items aren't actually used

            if self.sub_query > 0:
                log.info("The query couldn't be executed in one request, "
                         "separating it in sub-queries...")

                times = divide_times(
                    first=self.start_time, last=self.end_time, slots=self.nitro.config.async_slots)
                sub_queries = list()

                for time in times:
                    sub_query = copy.copy(self)

                    sub_query.time_range = 'CUSTOM'
                    sub_query.start_time = time[0].isoformat()
                    sub_query.end_time = time[1].isoformat()
                    sub_query.sub_query -= 1
                    sub_queries.append(sub_query)

                [log.debug(sub_query) for sub_query in sub_queries]

                results = Manager.__perform(QueryManager.action_load_data, sub_queries,
                                            asynch=(sub_query == 1), progress=True)

                # Flatten the list of lists in a list
                return(QueryManager([item for sublist in results for item in sublist]))

            else:
                log.warning(
                    "The query couldn't be fully executed after the maximum number of sub_queries.")
                return QueryManager(items)
        else:
            return QueryManager(items)
