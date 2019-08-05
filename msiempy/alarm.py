"""Provide alarm management.
"""

import collections
import datetime
import logging
log = logging.getLogger('msiempy')

from . import NitroDict, NitroList
from .query import FilteredQueryList
from .event import EventManager, Event
from .utils import regex_match, convert_to_time_obj

class AlarmManager(FilteredQueryList):
    """
    AlarmManager class.
    Interface to query and manage Alarms.
    Inherits from FilteredQueryList.
    """
    def __init__(self, status_filter='all', page_size=None, page_number=None, filters=None, *args, **kwargs):

        """
        Parameters:  
        
        - `status_filter` : status of the alarms to query
        - `page_size` : max number of rows per query, by default takes the value in config `default_rows` option.
        - `page_number` : defaulted to 1.
        - `filters` : [(field, [values]), (field, [values])]
        - `fields` : list of strings. Can be an EsmTriggeredAlarm or an EsmTriggeredAlarmEvent field, or any synonims. See 
        - `*args, **kwargs` : Parameters passed to `msiempy.base.FilteredQueryList.__init__()`
            
        Examples:  
        ```>>>alarm_list=AlarmManager(status_filter='unacknowledged',
            filters=[('sourceIp','^10.*'), ('ruleMessage','Wordpress')]).load_data()```
        """

        super().__init__(*args, **kwargs)

        #Declaring attributes
        self._alarm_filters = list(tuple())
        self._event_filters = list(tuple())
        self._status_filter = str()

        #Setting attributes
        self.status_filter=status_filter
        self.page_size=page_size if page_size is not None else self.requests_size #IGNORE THE CONFIG
        self.requests_size=self.page_size
        self.page_number=page_number if page_number is not None else 1

        #uses the parent filter setter
        #TODO : find a soltuion not to use this stinky tric
        #callign super().filters=filters #https://bugs.python.org/issue14965
        super(self.__class__, self.__class__).filters.__set__(self, filters)

        #Casting all data to Alarms objects, better way to do it ?
        collections.UserList.__init__(self, [Alarm(adict=item) for item in self.data if isinstance(item, (dict, NitroDict))])

    @property
    def table_colums(self):
        """

        """
        return ['id','alarmName', 'triggeredDate', 'events']

    @property
    def filters(self):
        """
        Returns the addition of alarm related filters and event related filters.
        """
        return self._alarm_filters + self._event_filters
    
    @property
    def status_filter(self):
        """
        Status of the alarms in the query. `status_filter` is not a filter like other cause it's computed on the SIEM side.
        Other filters are computed locally - Unlike EventManager filters. the status filter of the alarm query. 'acknowledged', 'unacknowledged', 'all', '' or null -> all (default is '').
        You can pass synonims of each status. See `msiempy.alarm.Alarm.POSSIBLE_ALARM_STATUS`.
        """
        return self._status_filter
        """
        for synonims in Alarm.POSSIBLE_ALARM_STATUS :
            if self._status_filter in synonims :
                return synonims[0]"""

    @status_filter.setter
    def status_filter(self, status_filter):
        status_found=False
        if type(status_filter) is str : 
            for synonims in Alarm.POSSIBLE_ALARM_STATUS :
                if status_filter in synonims:
                    self._status_filter=synonims[0]
                    status_found=True
                
        if not status_found:
            raise AttributeError("Illegal value of status filter. The status must be in "+str(Alarm.POSSIBLE_ALARM_STATUS)+' not :'+str(status_filter))

    def add_filter(self, afilter):
        """
            Make sure the filters format is tuple(field, list(values in string)).
            Takes also care of the differents synonims fields can have.
        """

        if isinstance(afilter,str):
            afilter = afilter.split('=',1)
        try:
            values = afilter[1] if isinstance(afilter[1], list) else [afilter[1]]
            values = [str(v) for v in values]
            added=False

            for synonims in Alarm.ALARM_FILTER_FIELDS :
                if afilter[0] in synonims :
                    self._alarm_filters.append((synonims[0], values))
                    added=True

            for synonims in Alarm.ALARM_EVENT_FILTER_FIELDS :
                if afilter[0] in synonims :
                    self._event_filters.append((synonims[0], values))
                    added=True

        except IndexError:
            added = False

        if not added :
            raise AttributeError("Illegal filter field value : "+afilter[0]+". The filter field must be in :"+str(Alarm.ALARM_FILTER_FIELDS + Alarm.ALARM_EVENT_FILTER_FIELDS))

    def clear_filters(self):
        """
        Reset local alarm and event filters.
        """
        self._alarm_filters = list(tuple())
        self._event_filters = list(tuple())

    def load_data(self, **kwargs):
        """
        Specialized load_data() method that convert the `msiempy.base.FilteredQueryList.load_data()` result to AlarmManager object.
        kwargs are passed to super().load_data()
        """
        return AlarmManager(alist=super().load_data(**kwargs))

    def load_events(self, workers=20, extra_fields=None, by_id=False):
        """
        Returns a new NitroList with full detailled events fields
        """
        self.perform(
            Alarm.load_events,
            asynch=True,
            workers=workers,
            progress=True,
            func_args=dict(extra_fields=extra_fields, by_id=by_id))
        return AlarmManager(alist=self)

    def _load_data(self, workers):
        """
        Concrete helper method that loads the data.
            -> Fetch the complete list of alarms -> Filter
            
        #TODO move filtering part somewhere else
        """
        alarms=list()
        if self.time_range == 'CUSTOM' :
            alarms=self.nitro.request(
                'get_alarms_custom_time',
                time_range=self.time_range,
                start_time=self.start_time,
                end_time=self.end_time,
                status=self.status_filter,
                page_size=self.page_size,
                page_number=self.page_number
                )

        else :
            alarms=self.nitro.request(
                'get_alarms',
                time_range=self.time_range,
                status=self.status_filter,
                page_size=self.page_size,
                page_number=self.page_number
                )
        #alarms = AlarmManager(alist=alarms)
        return (( self._filter(alarms, workers), len(alarms)<self.page_size ))

    def _filter(self, alarms, workers, alarmonly=False):
        """
        Helper method that filters the alarms depending on alarm and event filters.
            -> Filter dependinf on alarms related filters -> load events details
                -> Filter depending on event related filters
        Returns a AlarmsNitroList
    
        """

        alarms = AlarmManager(alist=[a for a in alarms if self._alarm_match(a)])

        if not alarmonly :
            log.info("Getting alarms infos... Please be patient.")
            detailed = self.perform(Alarm.load_details, list(alarms), asynch=True, progress=True, workers=workers)
            alarms = AlarmManager(alist=[a for a in detailed if self._event_match(a)])

        log.info(str(len(alarms)) + " alarms matching your filter(s)")
        return alarms

    def _alarm_match(self, alarm):
        """
        Filter method that is going to return True if the passed alarm match any alarm related filters.
        """
        match=True
        for alarm_filter in self._alarm_filters :
            match=False
            value = str(alarm[alarm_filter[0]]) #Can only match strings
            for filter_value in alarm_filter[1]:
                if regex_match(filter_value.lower(), value.lower()):
                    match=True
                    break
            if not match :
                break
        return match
        
    def _event_match(self, alarm):
        """
        Filter method that is going to return True if the passed alarm match any event related filters.
        """
        match=True
        for event_filter in self._event_filters :
            match=False
            values = [str(event[event_filter[0]]) for event in alarm['events']] #Can only match strings
            for filter_value in event_filter[1]:
                if any(regex_match(filter_value.lower(), value.lower()) for value in values):
                    match=True
                    break
            if not match :
                break
        return match
        
class Alarm(NitroDict):
    """
    Dict keys :  
        - `id` : The ID of the triggered alarm
        - `summary`  : The summary of the triggered alarm
        - `assignee` : The assignee for this triggered alarm
        - `severity` : The severity for this triggered alarm
        - `triggeredDate` : The date this alarm was triggered
        - `acknowledgedDate` : The date this triggered alarm was acknowledged
        - `acknowledgedUsername` : The user that acknowledged this triggered alarm
        - `alarmName` : The name of the alarm that was triggered
        - `events` : The events for this user
        - And others...
    
    """

    """@property
    def status(self):
        return('acknowledged' 
            if ( (len(self.data['acknowledgedDate'])>0) 
                and (len(self.data['acknowledgedUsername'])>0))
            else 'unacknowledged')"""

    POSSIBLE_ALARM_STATUS=[
        ['acknowledged', 'ack',],
        ['unacknowledged', 'unack',],
        ['', 'all', 'both']
    ]
    """
    Possible alarm statuses : `'acknowledged', 'unacknowledged' or ''`. Some synonims can also be used, see source code.
    """

    ALARM_FILTER_FIELDS = [('id',),
    ('summary','sum'),
    ('assignee','user'),
    ('severity','sever'),
    ('triggeredDate','trigdate'),
    ('acknowledgedDate','ackdate'),
    ('acknowledgedUsername','ackuser'),
    ('alarmName','name'),
    ]
    """
    Possible fields usable in a alarm filter : `'id', 'summary', 'assignee', 'severity', 'triggeredDate', 'acknowledgedDate', 'acknowledgedUsername', 'alarmName'`. 
    Some synonims can also be used, see source code.
    """

    ALARM_EVENT_FILTER_FIELDS=[("eventId",),
    #"severity", duplicated in ALARM_FILTER_FIELD
    #("severity", "eventseverity",),
    ("ruleMessage",'msg','rulemsg'),
    ("eventCount",'count'),
    ("sourceIp",'srcip'),
    ("destIp",'dstip'),
    ("protocol",'prot'),
    ("lastTime",'date'),
    ("eventSubType",'subtype')]
    """
    Possible fields usable in a event filter : `'eventID', 'ruleMessage', 'eventCount', 'sourceIp', 'destIp', 'protocol', 'lastTime', 'eventSubType'`.
    Some synonims can also be used, see source code.

    """

    ALARM_DEFAULT_FIELDS=['triggeredDate','alarmName','status','sourceIp','destIp','ruleMessage']
    """Defaulfs fields : `'triggeredDate','alarmName','status','sourceIp','destIp','ruleMessage'` (not used , may be for printing with `msiempy.NitroList.get_text(fields=msiempy.alarm.ALARM_DEFAULT_FIELDS)`)
    """

    def __init__(self, *arg, **kwargs):
        """Creates a empty AlarmManager.
        """
        super().__init__(*arg, **kwargs)

    def acknowledge(self):
        """Mark the alarm as acknowledged.
        """
        self.nitro.request('ack_alarms', ids=[self.data['id']['value']])

    def unacknowledge(self):
        """Mark the alarm as unacknowledge.    
        """
        self.nitro.request('unack_alarms', ids=[self.data['id']['value']])

    def delete(self):
        """Destructive action!
        Delete the alarm.
        """
        self.nitro.request('delete_alarms', ids=[self.data['id']['value']])

    def ceate_case(self):
        """Not implemented : TODO
        """
        raise NotImplementedError()

    def load_details(self):
        """Update the alarm with detailled data loaded from the SIEM.
        """
        the_id = self.data['id']
        self.data.update(self.data_from_id(the_id))
        self.data['id']=the_id
        return self

    def refresh(self):
        """Update the alarm with detailled data loaded from the SIEM. Concrete NitroObject method.
        """
        self.load_details()

    def load_events(self, extra_fields=None, by_id=False):
        """
        Retreive the genuine Event object from an Alarm.
        Parameters:  
        - `extra_fields` : List of extra fields. Reminder, defaul fields : `msiempy.event.Event.DEFAULTS_EVENT_FIELDS`
        - `by_id` : Will seek for event data using the getAlertData SIEM api call. (doesn't work TODO ) 
        If not, will use qryExecuteDetails and with a timedeal +-1second and some ip source/destination filter.
        """
        events=self.data['events']
        filters = list()
        
        if by_id==True :
            for event in events:
                try :
                    event.data=Event(id=event['Alert.IPSIDAlertID'])
                except TypeError as err:
                    #TODO Make it work !
                    log.warning("The event could not be loaded from the id : {}".format(event))
                    

        elif by_id==False:

            for event in events:
                if len(event['sourceIp']) >= 7 :
                    filters.append(('SrcIP', [str(event['sourceIp'])]))
                if len(event['destIp']) >= 7 :
                    filters.append(('DstIP', [str(event['destIp'])]))

            log.debug("Filters : "+str(filters))
            events = EventManager(
                start_time=convert_to_time_obj(events[0]['lastTime'])-datetime.timedelta(seconds=1),
                end_time=convert_to_time_obj(events[-1]['lastTime'])+datetime.timedelta(seconds=1),
                filters=filters,
                fields=extra_fields,
                max_query_depth=0,
                limit=100
            ).load_data()

            match='|'.join([event['eventId'].split('|')[1] for event in self.data['events']])
            events = EventManager(alist=events.search(match))
            self.data['events']=events

        return events

    def data_from_id(self, id):
        """

        """
        return self.nitro.request('get_alarm_details', id=str(id))

    """
    def _hasID(self):
        try :
            if self.data['id']['value'] == 0 :
                return False
            else :
                return True
        
        except KeyError :
            return False"""

