"""Provide alarm management.  
"""
import collections
import logging

log = logging.getLogger("msiempy")

from .core import NitroDict, FilteredQueryList
from .event import Event, EventManager
from .core.utils import regex_match, dehexify

__pdoc__ = {}


class AlarmManager(FilteredQueryList):
    """
    Interface to query and manage Alarms.
    Inherits from `msiempy.core.query.FilteredQueryList`.

    Arguments:

    - `status_filter` : status of the alarms to query. `status_filter` is not a filter like other cause it's computed on the SIEM side.
    Accepted values : `acknowledged`, `unacknowledged`, `all`, `` or `None` (default is ``).
    `filters` are computed locally - Unlike `msiempy.event.EventManager` filters.
    - `page_size` : max number of rows per query.
    - `page_number` : defaulted to 1.
    - `filters` : `[(field, [values]), (field, [values])]` Filters applied to `msiempy.alarm.Alarm` objects. A single `tuple` is also accepted.
    - `event_filters` : `[(field, [values]), (field, [values])]` Filters applied to `msiempy.event.Event` objects. A single `tuple` is also accepted.
    - `time_range` : Query time range. String representation of a time range.
    - `start_time` : Query starting time, can be a `string` or a `datetime` object. Parsed with `dateutil`.
    - `end_time` : Query endding time, can be a `string` or a `datetime` object. Parsed with `dateutil`.

    **Unlike `EventManager`, filters are computed after the data loaded with regex matching.**

    """

    def __init__(
        self, *args, status_filter="all", page_size=200, event_filters=None, **kwargs
    ):

        # Declaring attributes before calling super() because it would overwrite values
        self._alarm_filters = []
        self._event_filters = []

        super().__init__(*args, **kwargs)

        self._status_filter = str()

        # Setting attributes
        self.status_filter = status_filter
        """
        Alarms status filter
        """

        self.page_size = page_size
        """
        Maximum number of alarms per query
        """

        # uses the parent filter setter
        # TODO : find a soltuion not to use this
        # calling super().filters=filters #https://bugs.python.org/issue14965
        # super(self.__class__, self.__class__).filters.__set__(self, filters)

        # Seeting events filters after alarms filters cause it would overwrite it
        self.event_filters = event_filters

        # Casting all data to Alarms objects, better way to do it ?
        collections.UserList.__init__(
            self,
            [
                Alarm(adict=item)
                for item in self.data
                if isinstance(item, (dict, NitroDict))
            ],
        )

    def _get_filters(self):
        """
        The alarm related filters
        """
        return self._alarm_filters

    @property
    def status_filter(self):
        """
        Status of the alarms in the query.
        """
        return self._status_filter

    @status_filter.setter
    def status_filter(self, status_filter):
        status_found = False
        if type(status_filter) is str:
            for synonims in Alarm.POSSIBLE_ALARM_STATUS:
                if status_filter in synonims:
                    self._status_filter = synonims[0]
                    status_found = True

        if not status_found:
            raise AttributeError(
                "Illegal value of status filter. The status must be in "
                + str(Alarm.POSSIBLE_ALARM_STATUS)
                + " not :"
                + str(status_filter)
            )

    def add_filter(self, afilter):
        """
        Add a filter to the alarm query.

        Some event related filters can be added with this method. See `Alarm.ALARM_EVENT_FILTER_FIELDS`.

        Arguments :

        - `afilter` : Can be a a tuple `(field, [values])` or `(field, value)` or `str` 'field=value'

        Filters format is `tuple(field, [values])`.
        """

        if isinstance(afilter, str):
            afilter = afilter.split("=", 1)

        values = afilter[1] if isinstance(afilter[1], list) else [afilter[1]]
        values = [str(v) for v in values]
        added = False

        for field_name in Alarm.ALARM_EVENT_FILTER_FIELDS:
            if afilter[0] == field_name:
                log.warning(
                    "Passing event related filters in `filters` argument only works for a couple field names, consider using `event_filters` argument to use any field name.  "
                )
                self._event_filters.append((field_name, values))
                added = True

        # support query related filtering if the filter's field is composed by a table name then a field name separated by a dot.
        if len(afilter[0].split(".")) == 2:
            self._event_filters.append((afilter[0], values))
            added = True

        if added == False:
            self._alarm_filters.append((afilter[0], values))
            added = True

    @property
    def event_filters(self):
        """Event related filters."""
        return self._event_filters

    @event_filters.setter
    def event_filters(self, filters):
        if isinstance(filters, list):
            for f in filters:
                self.add_event_filter(f)

        elif isinstance(filters, tuple):
            self.add_event_filter(filters)

        elif filters == None:
            self._event_filters = list(tuple())

        else:
            raise AttributeError(
                "Illegal type for the filter object, it must be a list, a tuple or None."
            )

    def add_event_filter(self, afilter):
        """
        Add a event filter to the query.

        Arguments :

        - `afilter` : Can be a a tuple `(field, [values])` or `(field, value)` or `str` 'field=value'

        Filters format is `tuple(field, [values])`.
        """

        if isinstance(afilter, str):
            afilter = afilter.split("=", 1)

        values = afilter[1] if isinstance(afilter[1], list) else [afilter[1]]
        values = [str(v) for v in values]
        self._event_filters.append((afilter[0], values))

    def clear_filters(self):
        """
        Reset local alarm and event filters.
        """
        self._alarm_filters = []
        self._event_filters = []

    def load_data(self, pages=1, **kwargs):
        """
        Load the data into the list.
        Implements automatic paging over `msiempy.alarm.AlarmManager.qry_load_data`.
        Default behaviour is to load all alarms informations. Meaning that foreach alarms,
        the full details is loaded, then the trigerring event details is loaded.

        Arguments :

        - `pages` : Number of pages to load (not asynchronous).

        Arguments passed to `msiempy.alarm.AlarmManager.qry_load_data` :

        - `workers` : Number of asynchronous workers
        - `alarms_details` : Load detailed alarms infos. If `False`, only a couple values are loaded, no `events` infos.
        - `events_details` : Load detailed events infos. If `False`, no detailed `events` will be loaded. Only `str` representation for SIEM 10.x and minimal events records from SIEM 11.x.
        - `use_query` : Uses the query module to retreive event data. Only works with SIEM v11.2.1 or greater.
        Default behaviour will call `ipsGetAlertData` to retreive the complete event definition.
        - `extra_fields` :  Only when `use_query=True`. Additionnal event fields to load in the query. See : `msiempy.event.EventManager`
        - `page_number` : Page number, default to 1. Do not touch if you're using `pages` parameter

        Returns : `msiempy.alarm.AlarmManager`
        """

        items, completed = self.qry_load_data(**kwargs)
        # Casting items to Alarms
        alarms = [Alarm(adict=item) for item in items]

        # Iterative automatic paging (not asynchronous)
        if not completed and pages > 1:
            next_kwargs = {**kwargs}
            if "page_number" in kwargs:
                next_kwargs["page_number"] = kwargs["page_number"] + 1
            else:
                next_kwargs["page_number"] = 2

            log.info("Loading pages... ({})".format(next_kwargs["page_number"]))
            alarms = alarms + list(self.load_data(pages=pages - 1, **next_kwargs))

        if "page_number" not in kwargs:
            log.info(str(len(alarms)) + " alarms are matching your filter(s)")

        self.data = alarms
        return self

    def qry_load_data(
        self,
        workers=10,
        alarms_details=True,
        events_details=True,
        use_query=False,
        extra_fields=[],
        page_number=1,
    ):
        """
        Method that query, filter and return the alarms data :
        -> Fetch the list of alarms and load alarms details
        -> Filter depending on alarms related filters
        -> Load the events details
        -> Filter depending on event related filters

        Arguments :

        - `workers` : Number of asynchronous workers
        - `alarms_details` : Load detailed alarms infos. If `False`, only a couple values are loaded, no `events` infos.
        - `events_details` : Load detailed events infos. If `False`, no detailed `events` will be loaded only `str` representation.
        - `use_query` : Uses the query module to retreive event data. Only works with SIEM v11.2.1 or greater.
        - `extra_fields` :  Only when `use_query=True`. Additionnal event fields to load in the query. See : `msiempy.event.EventManager`
        - `page_number` : Page number, default to 1. Do not touch if you're using `pages` parameter

        Returns : `tuple` : ( Results : `list` , Status of the query : `completed` )

        """

        if self.time_range == "CUSTOM":
            no_filtered_alarms = self.nitro.request(
                "get_alarms_custom_time",
                time_range=self.time_range,
                start_time=self.start_time,
                end_time=self.end_time,
                status=self.status_filter,
                page_size=self.page_size,
                page_number=page_number,
            )

        else:
            no_filtered_alarms = self.nitro.request(
                "get_alarms",
                time_range=self.time_range,
                status=self.status_filter,
                page_size=self.page_size,
                page_number=page_number,
            )

        # Casting to list of Alarms to be able to call load_details etc...
        alarm_based_filtered = AlarmManager(
            [a for a in no_filtered_alarms if self._alarm_match(a)]
        )

        if alarms_details:

            log.info("Getting alarms infos...")
            alarm_based_filtered.perform(
                Alarm.load_details, asynch=True, progress=True, workers=workers
            )

            # Casting to list of Alarms to be able to call load_details etc...
            detailed_alarm_based_filtered = AlarmManager(
                [a for a in alarm_based_filtered if self._alarm_match(a)]
            )

            if events_details:
                log.info("Getting full events infos...")
                detailed_alarm_based_filtered.perform(
                    Alarm.load_events,
                    func_args=dict(use_query=use_query, extra_fields=extra_fields),
                    asynch=True,
                    progress=True,
                    workers=workers,
                )

            filtered_alarms = AlarmManager(
                [a for a in detailed_alarm_based_filtered if self._event_match(a)]
            )
        else:
            filtered_alarms = alarm_based_filtered
            log.warning(
                "Event filters and some Alarm filters are ignored when `alarms_details is False`"
            )

        return (filtered_alarms, len(no_filtered_alarms) < int(self.page_size))

    def _alarm_match(self, alarm):
        """
        Internal filter method that is going to return True if the passed alarm match all alarm related filters.
        """
        match = True
        for alarm_filter in self._alarm_filters:
            match = False
            try:
                value = str(alarm[alarm_filter[0]])  # Can only match strings
            except KeyError:
                break
            for filter_value in alarm_filter[1]:
                if regex_match(filter_value.lower(), value.lower()):
                    match = True
                    break
            if not match:
                break
        return match

    def _event_match(self, alarm):
        """
        Internal filter method that is going to return True if the passed alarm match all event related filters.
        """
        match = True
        for event_filter in self._event_filters:
            match = False
            try:
                value = str(alarm["events"][0][event_filter[0]])
            except KeyError:
                break
            for filter_value in event_filter[1]:
                if regex_match(filter_value.lower(), value.lower()):
                    match = True
                    break
            if not match:
                break
        return match


class Alarm(NitroDict):
    """
    Dict-Like object.

    Common keys :

    - `id` : The ID of the triggered alarm
    - `summary`  : The summary of the triggered alarm
    - `assignee` : The assignee for this triggered alarm
    - `severity` : The severity for this triggered alarm
    - `triggeredDate` : The date this alarm was triggered
    - `acknowledgedDate` : The date this triggered alarm was acknowledged
    - `acknowledgedUsername` : The user that acknowledged this triggered alarm
    - `alarmName` : The name of the alarm that was triggered
    - `events` : The events that triggered the alarm
    - And others...

    Arguments:

    - `adict`: Alarm parameters
    - `id`: The alarm ID to instanciate. Will load informations
    """

    def __init__(self, *arg, **kwargs):
        """Creates a empty Alarm."""
        super().__init__(*arg, **kwargs)

        # Keep the id in the dict when instanciating an Alarm directly from its id.
        if "id" in kwargs:
            self.data["id"] = {"value": str(kwargs["id"])}
        # Casting all events to Event object
        if "events" in self.data and isinstance(self.data["events"], list):
            self["events"] = EventManager(self.data["events"])

    POSSIBLE_ALARM_STATUS = [
        [
            "acknowledged",
            "ack",
        ],
        [
            "unacknowledged",
            "unack",
        ],
        ["", "all", "both"],
    ]
    __pdoc__[
        "Alarm.POSSIBLE_ALARM_STATUS"
    ] = """Possible alarm statuses : ```%(statuses)s```""" % dict(
        statuses=", ".join(["/".join(synonims) for synonims in POSSIBLE_ALARM_STATUS])
    )

    ALARM_EVENT_FILTER_FIELDS = [
        "ruleName",
        "ruleMessage",
        "srcIp",
        "sourceIp",
        "destIp",
        "protocol",
        "lastTime",
        "subtype",
        "destPort",
        "destMac",
        "srcMac",
        "srcPort",
        "deviceName",
        "sigId",
        "normId",
        "srcUser",
        "destUser",
        "normMessage",
        "normDesc",
        "host",
        "domain",
        "ipsId",
    ]
    """Few Events fields names can be automatically added as event's filters when passing to `AlarmManager()`'s `filter` argument. See `msiempy.event.Event`.  """

    ALARM_DEFAULT_FIELDS = [
        "id",
        "alarmName",
        "summary",
        "triggeredDate",
        "acknowledgedUsername",
    ]
    __pdoc__["Alarm.ALARM_DEFAULT_FIELDS"] = (
        """`%(fields)s`. Just a list of regular fields.  Can bu useful for printing with `AlarmManager.get_text(fields=msiempy.alarm.ALARM_DEFAULT_FIELDS)`"""
        % dict(fields=", ".join(ALARM_DEFAULT_FIELDS))
    )

    def acknowledge(self):
        """Mark the alarm as acknowledged."""
        if self.nitro.api_v == 1:
            self.nitro.request("ack_alarms", ids=self.data["id"]["value"])
        else:
            self.nitro.request("ack_alarms_11_2_1", ids=self.data["id"]["value"])

    def unacknowledge(self):
        """Mark the alarm as unacknowledge."""
        if self.nitro.api_v == 1:
            self.nitro.request("unack_alarms", ids=self.data["id"]["value"])
        else:
            self.nitro.request("unack_alarms_11_2_1", ids=self.data["id"]["value"])

    def delete(self):
        """Destructive action!
        Delete the alarm.
        """
        if self.nitro.api_v == 1:
            self.nitro.request("delete_alarms", ids=self.data["id"]["value"])
        else:
            self.nitro.request("delete_alarms_11_2_1", ids=self.data["id"]["value"])

    def ceate_case(self):
        """Not implemented : TODO"""
        raise NotImplementedError()

    def load_details(self):
        """Update the alarm with detailled data loaded from the SIEM."""
        the_id = self.data["id"]["value"]
        self.data.update(self.data_from_id(the_id))
        if isinstance(self.data["events"], (list)):
            self["events"] = EventManager(self.data["events"])
        self.data["id"]["value"] = the_id

        return self

    def refresh(self):
        """Update the alarm with detailled data loaded from the SIEM."""
        self.load_details()

    def load_events(self, use_query=False, extra_fields=[], workers=1):
        """
        Retreive the complete trigerring Event(s) objects from an Alarm.
        This methos is automatically called automatically by default when calling `load_data()`.
        Arguments:

        - `use_query` : Uses the query module to retreive the event(s) data. Only works with SIEM v 11.2 or greater.
        Default behaviour will call `ipsGetAlertData` to retreive the complete event definition.
        - `extra_fields` : Only when `use_query=True`. Additionnal event fields to load in the query. See : `msiempy.event.EventManager`
        - `workers`: The number of asynchronous workers.

        .. Warning:: On SIEM v10.X This method will only load the details of the first triggering event.
        """
        if isinstance(self.data["events"], str):

            # Retreive the alert id from the event's string
            events_data = self.data["events"].split("|")
            the_id = events_data[0] + "|" + events_data[1]

            # instanciate the event
            the_first_event = Event()
            the_first_event.data = Event().data_from_id(
                id=the_id, use_query=use_query, extra_fields=extra_fields
            )

            # set it as the only item of the event list
            self.data["events"] = [the_first_event]

        elif isinstance(self.data["events"], (EventManager)):
            # The list has been loaded from notifyGetTriggeredNotificationDetail
            self.data["events"].perform(
                Event.refresh,
                asynch=True,
                workers=workers,
                func_args=dict(use_query=use_query, extra_fields=extra_fields),
            )
        else:
            log.info(
                "The alarm {} ({}) has no events associated".format(
                    self.data["alarmName"], self.data["triggeredDate"]
                )
            )
            self.data["events"] = [Event()]

        return self

    ALARM_FIELDS_MAP = {
        "EC": None,
        "SMRY": "summary",
        "NAME": "alarmName",
        "FILTERS": "filters",
        "CTYPE": None,
        "QID": "queryId",
        "ARM": "alretRateMin",
        "ARC": "alertRateCount",
        "PCTA": "percentAbove",
        "PCTB": "percentBelow",
        "OFFSETMIN": "offsetMinutes",
        "TIMEF": "maximumConditionTriggerFrequency",
        "XMIN": None,
        "USEW": "useWatchlist",
        "MFLD": "matchField",
        "MVAL": "matchValue",
        "SVRTY": "severity",
        "ASNID": "assigneeId",
        "ASNNAME": "assignee",
        "TRGDATE": "triggeredDate",
        "ACKDATE": "acknowledgedDate",
        "ESCDATE": "escalatedDate",
        "CASEID": "caseId",
        "CASENAME": "caseName",
        "IOCNAME": "iocName",
        "IOCID": "iocId",
        "DESC": "description",
        "NID": None,
        "ACTIONS": "actions",
        "NE": None,
        "EVENTS": "events",
        "DCHNG": None,
    }
    """
    List of all `Alarm` possible fields.  
    This is used only when the private API is used to retreive Alarm infos.  
    To change genuine (UPPERCASE) key names to more explicit ones matching public API names.  

    """

    def map_alarm_int_fields(self, alarm_details):
        """
        Map the internal ESM field names to msiempy style with `msiempy.alarm.Alarm.ALARM_FIELDS_MAP`.
        Converts "T" and "F" to `True` and `False` and handle None values.
        """

        for key, val in alarm_details.items():
            if alarm_details[key] == key:
                alarm_details[key] = None
            elif alarm_details[key] in ["f", "F"]:
                alarm_details[key] = False
            elif alarm_details[key] in ["t", "T"]:
                alarm_details[key] = True
            else:
                alarm_details[key] = val

        new_alarm = {}

        for priv_key in self.ALARM_FIELDS_MAP:
            new_alarm.__setitem__(
                self.ALARM_FIELDS_MAP[priv_key] or priv_key,
                alarm_details.get(priv_key) or None,
            )

        log.debug("NEW FULL alarm_details: " + str(new_alarm))

        return new_alarm

    def data_from_id(self, id, use_priv=False):
        """
        Gets the alarm parameters based on an ID.
        Will still use private method if SIEM if v10.X because it's the only way to get the trigerring event ID.

        Arguments:

        - `use_priv`: (`bool`): Use the private API methods to retreive the INFO, will use it anyway with ESM v10.x.
        Will only load the details of the first triggering event.

        """
        if self.nitro.esm_v.startswith(("10")) or use_priv:
            try:
                alarm = self.nitro.request("get_alarm_details_int", id=str(id))
                # Wrap arround private api call
                alarm = {
                    key: dehexify(val).replace("\n", "|") for key, val in alarm.items()
                }
                alarm = self.map_alarm_int_fields(alarm)
            except Exception as e:
                log.warning(
                    "Impossible to get the alarm data from the private API, trying with get_notification_detail call. Error: {}".format(
                        e
                    )
                )
                alarm = self.nitro.request("get_notification_detail", id=str(id))
                # Replace empty strings by None
                alarm = {
                    k: (v if v else None if isinstance(v, str) else v)
                    for k, v in alarm.items()
                }
        else:
            alarm = self.nitro.request("get_notification_detail", id=str(id))
            # Replace empty strings by None
            alarm = {
                k: (v if v else None if isinstance(v, str) else v)
                for k, v in alarm.items()
            }
        return alarm

    def get_id(self):
        """
        Return the alarm ID.
        """
        return self.data["id"]["value"]
