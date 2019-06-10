import collections
import datetime
import logging
log = logging.getLogger('msiempy')

from .base import Item, QueryManager, Manager
from .event import EventManager
from .utils import regex_match, convert_to_time_obj

class AlarmManager(QueryManager):
    """
    AlarmManager
    """
    def __init__(self, status_filter='all', page_size=None, page_number=None, filters=None, *args, **kwargs):

        """
        filters : [(field, [values]), (field, [values])]
        field can be an EsmTriggeredAlarm or an EsmTriggeredAlarmEvent field
        """

        super().__init__(*args, **kwargs)

        #Declaring attributes
        self._alarm_filters = list(tuple())
        self._event_filters = list(tuple())
        self._status_filter = str()

        #Setting attributes
        self.status_filter=status_filter
        self.page_size=page_size if page_size is not None else self.nitro.config.default_rows
        self.page_number=page_number if page_number is not None else 1

        #uses the parent filter setter
        super(self.__class__, self.__class__).filters.__set__(self, filters)

        collections.UserList.__init__(self, [Alarm(adict=item) for item in self.data if isinstance(item, (dict, Item))])

    @property
    def filters(self):
        return self._alarm_filters + self._event_filters
    
    @property
    def status_filter(self):
        return self._status_filter
        """
        for synonims in Alarm.POSSIBLE_ALARM_STATUS :
            if self._status_filter in synonims :
                return synonims[0]"""

    @status_filter.setter
    def status_filter(self, status_filter):
        """
        Set the status filter of the alarm query. 'acknowledged', 'unacknowledged', 'all', '' or null -> all (default is '')
        """
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
            Make sure the filters format is tuple(field, list(values in string))
            Takes also care of the differents synonims fields can have
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
        self._alarm_filters = list(tuple())
        self._event_filters = list(tuple())

    def load_data(self):
        return AlarmManager(alist=super().load_data())

    def _load_data(self):
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
        return (( self._filter(alarms), len(alarms)<self.page_size ))

    def _filter(self, alarms, alarmonly=False):
        
        alarms = AlarmManager(alist=[a for a in alarms if self._alarm_match(a)])

        if not alarmonly :
            log.info("Getting alarms infos... Please be patient.")
            detailed = self.perform(Alarm.action_load_details, list(alarms), asynch=True, progress=True)
            alarms = AlarmManager(alist=[a for a in detailed if self._event_match(a)])

        log.info(str(len(alarms)) + " alarms matching your filter(s)")
        return alarms

    def _alarm_match(self, alarm):
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
        
class Alarm(Item):
    """
    Alarm
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

    ALARM_FILTER_FIELDS = [('id',),
    ('summary','sum'),
    ('assignee','user'),
    ('severity','sever'),
    ('triggeredDate','trigdate'),
    ('acknowledgedDate','ackdate'),
    ('acknowledgedUsername','ackuser'),
    ('alarmName','name'),
    ]

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

    ALARM_DEFAULT_FIELDS=['triggeredDate','alarmName','status','sourceIp','destIp','ruleMessage']

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)

    def acknowledge(self):
        self.nitro.request('ack_alarms', ids=[self.data['id']['value']])

    def unacknowledge(self):
        self.nitro.request('unack_alarms', ids=[self.data['id']['value']])

    def delete(self):
        self.nitro.request('delete_alarms', ids=[self.data['id']['value']])

    def ceate_case(self):
        raise NotImplementedError()

    def load_details(self):
        details = self.nitro.request('get_alarm_details', id=self.data['id'])
        super().__init__(adict=details)
        return self

    def create_case(self):
        raise NotImplementedError()

    def refresh(self):
        super().refresh()

    def load_events_details(self):
        """
        
        """
        events=self.data['events']
        filters = list()

        for event in events:
            if len(event['sourceIp']) >= 7 :
                filters.append(('SrcIP', [str(event['sourceIp'])]))
            if len(event['destIp']) >= 7 :
                filters.append(('SrcIP', [str(event['destIp'])]))

        log.debug("Filters : "+str(filters))
        events = EventManager(
            start_time=convert_to_time_obj(events[0]['lastTime'])-datetime.timedelta(seconds=2),
            end_time=convert_to_time_obj(events[-1]['lastTime'])+datetime.timedelta(seconds=2),
            filters=filters
        ).load_data()

        match='|'.join([event['eventId'].split('|')[1] for event in self.data['events']])
        events = events.search(match)
        self.data['events']=events
        return events

    @staticmethod
    def action_delete(alarm):
        return alarm.delete()

    @staticmethod
    def action_acknowloedge(alarm):
        return alarm.acknowledge()

    @staticmethod
    def action_unacknowloedge(alarm):
        return alarm.unacknowledge()

    @staticmethod
    def action_create_case(alarm, case):
        return alarm.create_case(case)

    @staticmethod
    def action_load_details(alarm):
        return alarm.load_details()

    @staticmethod
    def action_load_events_details(alarm):
        return alarm.load_events_details()

    """
    def _hasID(self):
        try :
            if self.data['id']['value'] == 0 :
                return False
            else :
                return True
        
        except KeyError :
            return False"""