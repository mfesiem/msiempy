"""
HTTP level interface to the ESM API.  
"""
import logging
import requests
import json
import ast
import re
import urllib.parse
import inspect
import time
import urllib3
from urllib.parse import urlparse
from string import Template
from .utils import tob64
from .config import NitroConfig

log = logging.getLogger("msiempy")

__pdoc__ = {}  # Init pdoc to document dynamically

_PARAMS = {
    "login": (
        "login",
        Template(
            """{"username": "$username",
                "password" : "$password",
                "locale": "en_US",
                "os": "Win32"}
                """
        ),
    ),
    ### DATASOURCES
    "get_devtree": (
        "GRP_GETVIRTUALGROUPIPSLISTDATA",
        """{"ITEMS": "#{DC1 + DC2}",
                        "DID": "1",
                        "HD": "F",
                        "NS": "0"}
                    """,
    ),
    "get_zones_devtree": (
        "GRP_GETVIRTUALGROUPIPSLISTDATA",
        """{"ITEMS": "#{DC1 + DC2}",
                        "DID": "3",
                        "HD": "F",
                        "NS": "0"}
                    """,
    ),
    "req_client_str": (
        "DS_GETDSCLIENTLIST",
        Template(
            """{"DSID": "$ds_id",
                            "SEARCH": ""}
                        """
        ),
    ),
    "get_rfile": (
        "MISC_READFILE",
        Template(
            """{"FNAME": "$ftoken",
                "SPOS": "0",
                "NBYTES": "0"}
                """
        ),
    ),
    "del_rfile": ("ESSMGT_DELETEFILE", Template("""{"FN": "$ftoken"}""")),
    "get_rfile2": (
        "MISC_READFILE",
        Template(
            """{"FNAME": "$ftoken",
                "SPOS": "$pos",
                "NBYTES": "$nbytes"}
                """
        ),
    ),
    "get_wfile": (
        "MISC_WRITEFILE",
        Template(
            """{"DATA1": "$ds_id",
                        "PATH": "21",
                        "ND": "1"} """
        ),
    ),
    "get_rule_history": ("PLCY_GETRULECHANGEINFO", """{"SHOW": "F"}"""),
    # DO NOT DELETE
    # "map_dtree": ("map_dtree",
    #             Template("""{"dev_type": "$dev_type",
    #             "name": "$ds_name",
    #             "ds_id": "$ds_id",
    #             "enabled": "$enabled",
    #             "ds_ip": "$ds_ip",
    #             "hostname" : "$hostname",
    #             "typeID": "$type_id",
    #             "vendor": "",
    #             "model": "",
    #             "tz_id": "",
    #             "date_order": "",
    #             "port": "",
    #             "syslog_tls": "",
    #             "client_groups": "$client_groups"
    #             }
    #             """)),
    "add_ds_11_1_3": (
        "dsAddDataSource",
        Template(
            """{"datasource": {
                        "parentId": {"id": "$parent_id"},
                        "name": "$name",
                        "ipAddress": "$ds_ip",
                        "typeId": {"id": "$type_id"},
                        "zoneId": "$zone_id",
                        "enabled": "$enabled",
                        "url": "$url",
                        "id": {"id": "$ds_id"},
                        "childEnabled": "$child_enabled",
                        "childCount": "$child_count",
                        "childType": "$child_type",
                        "idmId": "$idm_id",
                        "parameters": $parameters
                    }}"""
        ),
    ),
    "add_ds_11_2_1": (
        "dsAddDataSources",
        Template(
            """{"receiverId": "$parent_id",
                        "datasources": [{
                            "name": "$name",
                            "ipAddress": "$ds_ip",
                            "typeId": {"id": "$type_id"},
                            "zoneId": "$zone_id",
                            "enabled": "$enabled",
                            "url": "$url",
                            "parameters": $parameters
                            }]}"""
        ),
    ),
    "add_client1": (
        "DS_ADDDSCLIENT",
        Template(
            """{"PID": "$parent_id",
                    "NAME": "$name",
                    "ENABLED": "$enabled",
                    "IP": "$ds_ip",
                    "HOST": "$hostname",
                    "TYPE": "$type_id",
                    "TZID": "$tz_id",
                    "DORDER": "$dorder",
                    "MASKFLAG": "$maskflag",
                    "PORT": "$port",
                    "USETLS": "$require_tls"
                    }"""
        ),
    ),
    "get_recs": (
        "devGetDeviceList?filterByRights=false",
        """{"types": ["RECEIVER"]}
                    """,
    ),
    "get_dstypes": (
        "dsGetDataSourceTypes",
        Template(
            """{"receiverId": {"id": "$rec_id"}
                        }
                    """
        ),
    ),
    "del_ds1": (
        "dsDeleteDataSource",
        Template(
            """{"receiverId": {"id": "$parent_id"},
                    "datasourceId": {"id": "$ds_id"}}
                """
        ),
    ),
    "del_ds2": (
        "dsDeleteDataSources",
        Template(
            """{"receiverId": {"value": "$parent_id"},
                    "datasourceIds": [{"value": "$ds_id"}]}
                """
        ),
    ),
    "del_client": (
        "DS_DELETEDSCLIENTS",
        Template(
            """{"DID": "$parent_id",
                            "FTOKEN": "$ftoken"}
                    """
        ),
    ),
    "get_job_status": ("MISC_JOBSTATUS", Template("""{"JID": "$job_id"}""")),
    "ds_last_times": ("QRY_GETDEVICELASTALERTTIME", """{}"""),
    "zonetree": ("zoneGetZoneTree", None),
    "ds_by_type": ("QRY_GETDEVICECOUNTBYTYPE", None),
    # DO NOT DELETE
    # "_dev_types":  ("dev_type_map",
    #                     """{"1": "zone",
    #                         "2": "ERC",
    #                         "3": "datasource",
    #                         "4": "Database Event Monitor (DBM)",
    #                         "5": "DBM Database",
    #                         "7": "Policy Auditor",
    #                         "10": "Application Data Monitor (ADM)",
    #                         "12": "ELM",
    #                         "14": "Local ESM",
    #                         "15": "Advanced Correlation Engine (ACE)",
    #                         "16": "Asset datasource",
    #                         "17": "Score-based Correlation",
    #                         "19": "McAfee ePolicy Orchestrator (ePO)",
    #                         "20": "EPO",
    #                         "21": "McAfee Network Security Manager (NSM)",
    #                         "22": "McAfee Network Security Platform (NSP)",
    #                         "23": "NSP Port",
    #                         "24": "McAfee Vulnerability Manager (MVM)",
    #                         "25": "Enterprise Log Search (ELS)",
    #                         "254": "client_group",
    #                         "256": "client"}
    #                     """),
    "ds_details1": (
        "dsGetDataSourceDetail",
        Template(
            """{"datasourceId": 
                            {"id": "$ds_id"}}
                        """
        ),
    ),
    "ds_details2": (
        "dsGetDataSourceDetail",
        Template("""{"datasourceId": {"value": "$ds_id"}}"""),
    ),
    ### ALARMS
    "get_alarms_custom_time": (
        Template(
            """alarmGetTriggeredAlarms?triggeredTimeRange=$time_range&customStart=$start_time&customEnd=$end_time&status=$status&pageSize=$page_size&pageNumber=$page_number"""
        ),
        None,
    ),
    "get_alarms": (
        Template(
            """alarmGetTriggeredAlarms?triggeredTimeRange=$time_range&status=$status&pageSize=$page_size&pageNumber=$page_number"""
        ),
        None,
    ),
    "get_notification_detail": (
        """notifyGetTriggeredNotificationDetail""",
        Template("""{"id":$id}"""),
    ),
    "get_alarm_details": (
        """notifyGetTriggeredNotification""",
        Template("""{"id":$id}"""),
    ),
    "get_alarm_details_int": (
        "NOTIFY_GETTRIGGEREDNOTIFICATIONDETAIL",
        Template("""{"TID": "$id"}"""),
    ),
    "ack_alarms": (
        """alarmAcknowledgeTriggeredAlarm""",
        Template("""{"triggeredIds":[{"value":$ids}]}"""),
    ),
    "ack_alarms_11_2_1": (
        """alarmAcknowledgeTriggeredAlarm""",
        Template("""{"triggeredIds":{"alarmIdList":[$ids]}}"""),
    ),
    "unack_alarms": (
        """alarmUnacknowledgeTriggeredAlarm""",
        Template("""{"triggeredIds":[{"value":$ids}]}"""),
    ),
    "unack_alarms_11_2_1": (
        """alarmUnacknowledgeTriggeredAlarm""",
        Template("""{"triggeredIds":{"alarmIdList":[$ids]}}"""),
    ),
    "delete_alarms": (
        """alarmDeleteTriggeredAlarm""",
        Template("""{"triggeredIds":[{"value":$ids}]}"""),
    ),
    "delete_alarms_11_2_1": (
        """alarmDeleteTriggeredAlarm""",
        Template("""{"triggeredIds":{"alarmIdList":[$ids]}}"""),
    ),
    "get_alerts_now": ("""IPS_GETALERTSNOW""", Template("""{"IPSID": "$ds_id"}""")),
    "get_flows_now": ("""IPS_GETFLOWSNOW""", Template("""{"IPSID": "$ds_id"}""")),
    ### QUERY MODULE
    "get_possible_filters": ("""v2/qryGetFilterFields""", None),
    "get_possible_fields": (
        Template("""v2/qryGetSelectFields?type=$type&groupType=$groupType"""),
        None,
    ),
    "event_query_custom_time": (
        """v2/qryExecuteDetail?type=EVENT&reverse=false""",
        Template(
            """{
                "config": {
                    "timeRange": "$time_range",
                    "customStart": "$start_time",
                    "customEnd": "$end_time",
                    "fields": $fields,
                    "filters": $filters,
                    "limit": $limit,
                    "offset": $offset,
                    "order": [{"field": {"name": "$order_field"},
                                            "direction": "$order_direction"}]
                    }
                    }"""
        ),
    ),
    "event_query": (
        """v2/qryExecuteDetail?type=EVENT&reverse=false""",
        Template(
            """{
                "config": {
                    "timeRange":"$time_range",
                    "fields":$fields,
                    "filters":$filters,
                    "limit":$limit,
                    "offset":$offset,
                    "order": [{"field": {"name": "$order_field"},
                                            "direction": "$order_direction"}]
                    }
                    }"""
        ),
    ),
    "query_status": ("""v2/qryGetStatus""", Template("""{"resultID": $resultID}""")),
    "query_result": (
        Template(
            """v2/qryGetResults?startPos=$startPos&numRows=$numRows&reverse=false"""
        ),
        Template("""{"resultID": $resultID}"""),
    ),
    "grouped_event_query": (
        """v2/qryExecuteGrouped?queryType=EVENT""",
        Template(
            """{
                "config": { 
                    "filters": $filters,
                    "field": {"name": "$field"},
                    "timeRange": "$time_range"
                    }
        }"""
        ),
    ),
    "grouped_event_query_custom_time": (
        """v2/qryExecuteGrouped?queryType=EVENT""",
        Template(
            """{
                "config": { 
                    "filters": $filters,
                    "field": {"name": "$field"},
                    "timeRange": "$time_range",
                    "customStart": "$start_time",
                    "customEnd": "$end_time",
                    }
        }"""
        ),
    ),
    "close_query": ("""v2/qryClose""", Template("""{"resultID": $resultID}""")),
    ### EVENTS OPERATIONS
    "get_alert_data": ("""ipsGetAlertData""", Template("""{"id": {"value":"$id"}}""")),
    "add_note_to_event": (
        """ipsAddAlertNote""",
        Template(
            """{
            "id": {"value": "$id"},
            "note": {"note": "$note"}
        }"""
        ),
    ),
    "add_note_to_event_int": (
        """IPS_ADDALERTNOTE""",
        Template(
            """{"AID": "$id",
                                                            "NOTE": "$note"}"""
        ),
    ),
    ### WATCHLISTS OPERATIONS
    "get_wl_types": ("""sysGetWatchlistFields""", None),
    "get_watchlists_no_filters": (
        Template(
            """sysGetWatchlists?hidden=$hidden&dynamic=$dynamic&writeOnly=$writeOnly&indexedOnly=$indexedOnly"""
        ),
        None,
    ),
    "get_watchlist_details": (
        """sysGetWatchlistDetails""",
        Template("""{"id": $id}"""),
    ),
    "add_watchlist": (
        """sysAddWatchlist""",
        Template(
            """{
            "watchlist": {
                "name": "$name",
                "type": {"name": "$wl_type",
                            "id": 0},
                "customType": {"name": "",
                                "id": 0},
                "dynamic": "False",
                "enabled": "True",
                "search": "",
                "source": 0,
                "updateType": "EVERY_SO_MANY_MINUTES",
                "updateDay": 0,
                "updateMin": 0,
                "ipsid": "0",
                "valueFile": {"fileToken": ""},
                "dbUrl": "",
                "mountPoint": "",    
                "path": "",
                "port": "22",
                "username": "",
                "password": "",
                "query": "",
                "lookup": "",
                "jobTrackerURL": "",
                "jobTrackerPort": "",
                "postArgs": "",
                "ignoreRegex": "",
                "method": 0,
                "matchRegex": "",
                "lineSkip": 0,
                "delimitRegex": "",
                "groups": 1
                            }}"""
        ),
    ),
    "add_watchlist_values": (
        """sysAddWatchlistValues""",
        Template(
            """{
            "watchlist": $watchlist,
            "values": $values,
            }"""
        ),
    ),
    "remove_watchlist_values": (
        """sysRemoveWatchlistValues""",
        Template(
            """{
            "watchlist": $watchlist,
            "values": $values,
            }"""
        ),
    ),
    "get_watchlist_values": (
        "SYS_GETWATCHLISTDETAILS",
        Template("""{"WID": "$id", "LIM": "T"}"""),
    ),
    "remove_watchlists": (
        """sysRemoveWatchlist""",
        Template("""{"ids": {"watchlistIdList": ["$wl_id_list"]}}"""),
    ),
    ### MISC
    "get_user_locale": ("""getUserLocale""", None),
    "time_zones": ("""userGetTimeZones""", None),
    "logout": ("""logout""", None),
    "get_sys_info": ("SYS_GETSYSINFO", """{}"""),
    "get_esm_time": ("""essmgtGetESSTime""", None),
    "build_stamp": ("essmgtGetBuildStamp", None),
}
"""

Central place to aggregate methods and parameters.


Important note : 
    Do not use sigle quotes (`'`) to delimit data into the interpolated strings !

"""

# Do not document esm_request() it's been replaced by api_request()
__pdoc__["NitroSession.esm_request"] = False


class NitroSession:
    """
    `msiempy.core.session.NitroSession` is the point of convergence of every requests that goes to the ESM.
    It provides easier dialogue with the ESM by doing argument interpolation with `msiempy.core.session.NitroSession.PARAMS`.

    Arguments:

    - `config` : `msiempy.core.config.NitroConfig` object, find default config if missing.

    See `msiempy.core.session.NitroSession.api_request` and `msiempy.core.session.NitroSession.request` for usage.

    """

    def __init__(self, config=None):

        self.__dict__ = NitroSession.__unique_state__

        # Init properties only once
        if NitroSession.__initiated__ == False:
            NitroSession.__initiated__ = True

            # Private attributes
            # self._headers={'Content-Type': 'application/json'}

            # Config parsing
            self.config = None
            """
            `msiempy.core.config.NitroConfig` object.  
            """

            if config == None:
                self.config = NitroConfig()
            else:
                if isinstance(config, NitroConfig):
                    self.config = config
                else:
                    raise TypeError(
                        "config must be a NitroConfig or None. Not {}".format(config)
                    )

            # Set the logging configuration
            self._init_log(
                verbose=self.config.verbose,
                quiet=self.config.quiet,
                logfile=self.config.logfile,
            )

            self.api_v = 0
            self.logged_in = False

            self.login_info = dict()
            """Login user infos as returned by `login` API method."""

            self.session = requests.Session()
            """Underlying `requests.Session` object. """

            try:
                requests.packages.urllib3.disable_warnings(
                    requests.packages.urllib3.exceptions.InsecureRequestWarning
                )
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except:
                pass

    BASE_URL = "https://{}/rs/esm/"
    """API base url: `'https://{}/rs/esm/'`"""

    BASE_URL_PRIV = "https://{}/ess/"
    """Private API base URL: `'https://{}/ess/'`"""

    __initiated__ = False
    """
    Weither the session has been intaciated. It's supposed to be a singleton.
    """
    __unique_state__ = {}
    """
    The singleton unique state.
    """

    PARAMS = _PARAMS
    """
    SIEM API methos/parameters mapping.  
    This structure provide a central place to aggregate API methods and parameters.  

    Usage: `NitroSession.PARAMS.get("method")`

    Returns:  
        - `tuple `: (`str` or `Template`, `str` or `Template`) :  
        The first item is the SIEM API endpoint name.  
        The second item is the JSON string data parameters required for the enpoint call. 
        If the string is `Template` string, it needs to be interpolate with paramaters.  

    See `msiempy.core.session.NitroSession.request` for a list of all possible calls.  
    """

    def __str__(self):
        return repr(self.__unique_state__)

    def login(self, retry=1):
        """Authentication is done lazily upon the first call to `msiempy.core.session.NitroSession.request` method, but you can still do it manually by calling this method.
        Throws `msiempy.core.session.NitroError` if login fails.
        """
        userb64 = tob64(self.config.user)
        passb64 = self.config.passwd

        self.session.headers = {"Content-Type": "application/json"}

        resp = self.request(
            "login", username=userb64, password=passb64, raw=True, secure=True
        )

        if resp != None:
            try:
                resp.raise_for_status()
            except requests.HTTPError as e:
                if retry > 0:
                    time.sleep(1)
                    return self.login(retry=retry - 1)
                else:
                    raise NitroError("ESM Login Error: ", resp.text) from e

            self.session.headers["Cookie"] = resp.headers.get("Set-Cookie")
            self.session.headers["X-Xsrf-Token"] = resp.headers.get("Xsrf-Token")

            self.user_tz_id = dict(resp.json())["tzId"]
            self.logged_in = True
            self.login_info = self._unpack_resp(resp)

            # Saving version number
            self.esm_v = self.version()
            # Shorthanding the 2019 API major changes
            # 10.4.x Release Notes: https://docs.mcafee.com/bundle/enterprise-security-manager-10.4.x-release-notes/page/GUID-53A62E21-F256-4D39-9B33-EDB3955FF7F2.html
            # 11.2.x Release Notes: https://docs.mcafee.com/bundle/enterprise-security-manager-11.2.x-release-notes/page/GUID-DD551A43-13A2-4649-B9C2-D618C291C9C2.html
            # 1 for pre 11.2.1, 2 for 11.2.1 and later
            # Not be confused with the ESM API v1 and v2 which are different.
            if self.esm_v.startswith(("9", "10", "11.0", "11.1")):
                self.api_v = 1
            else:
                self.api_v = 2

            log.info(
                "Logged into ESM {} with username {}. Last login {}".format(
                    str(self.config.host),
                    self.login_info["userName"],
                    self.login_info["lastLoginDate"],
                )
            )

            return True
        else:
            raise NitroError("ESM Login Error: Response empty")

    def logout(self):
        """
        This method will logout the session.
        """
        self.api_v = 0
        self.esm_v = "0"
        self.request("logout", http="delete")
        self.logged_in = False
        self.login_info = dict()
        self.session = requests.Session()
        self.user_tz_id = None

    def api_request(
        self,
        method,
        data=None,
        http="post",
        callback=None,
        raw=False,
        secure=False,
        retry=1,
    ):
        """
        Handle a lower level HTTP request to ESM API endpoints.

        Format the request, handle the basic parsing of the SIEM result as well as other errors.

        All upper cases method names signals to use the private API methods.

        Arguments:

        - `method` : ESM API enpoint name and url formatted parameters
        - `http`: HTTP method.
        - `data` : dict data to send
        - `callback` : function to apply afterwards
        - `raw` : If true will return the Response object from requests module. No retry when raw=True.
        - `secure` : If true will not log the content of the request.
        - `retry` : Number of time the request can be retried

        Returns:

        - a `dict`, `list` or `str` object.
        - the `resquest.Response` object if raw=True
        - `None` if Timeout or TooManyRedirects if raw=False

        Raises:

        - `msiempy.core.session.NitroError` if any `HTTPError`

        Note : Private API is under /ess/ and public api is under /rs/esm

        Exemple:

        ```python
        from msiempy import NitroSession
        s = NitroSession()
        s.login()
        # qryGetFilterFields
        s.api_request('qryGetFilterFields')
        # Get all last 24h alarms details with ESM API v2.
        alarms = s.api_request('v2/alarmGetTriggeredAlarms?triggeredTimeRange=LAST_24_HOURS&status=&pageSize=500&pageNumber=1', None)
        for a in alarms:
            a.update(s.api_request('v2/notifyGetTriggeredNotificationDetail', {'id':a['id']}))
        ```

        """

        url = ""
        privateApiCall = False
        result = None

        # Logging the data request if not secure | Logs anyway the method
        log.debug(
            "Requesting HTTP "
            + str(http)
            + " "
            + str(method)
            + (" with data " + str(data) if not secure else " ***")
        )

        http_data = ""

        # Handling private API calls formatting
        if method == method.upper():
            privateApiCall = True
            url = self.BASE_URL_PRIV
            http_data = self._format_params(method, **data)
            log.debug(
                "Private API call : "
                + str(method)
                + " Formatted params : "
                + str(http_data)
            )

        # Normal API calls
        else:
            url = self.BASE_URL
            if data:
                http_data = json.dumps(data)

        try:
            result = self.session.request(
                http,
                urllib.parse.urljoin(url.format(self.config.host), method),
                data=http_data,
                verify=self.config.ssl_verify,
                timeout=self.config.timeout,
                # Uncomment for debugging.
                # proxies={"http": "http://127.0.0.1:8888", "https":"http:127.0.0.1:8888"}
            )

            if raw:
                log.debug("Returning raw requests Response object : " + str(result))
                return result

            else:
                try:
                    result.raise_for_status()

                except requests.HTTPError as e:
                    error = None

                    if retry > 0:
                        # Invalid session handler -> re-login
                        if any(
                            [
                                match in result.text
                                for match in [
                                    "ERROR_InvalidSession",
                                    "ERROR_INVALID_SESSION",
                                    "Not Authorized User",
                                    "Invalid Session",
                                    "Username and password cannot be null",
                                ]
                            ]
                        ):
                            error = NitroError(
                                "Authentication error with method ({}) and data : {} logging in and retrying api_request(). From requests.HTTPError {} {}".format(
                                    method, data, e, result.text
                                )
                            )
                            log.warning(error)
                            self.logged_in = False
                            self.login()

                        else:
                            log.warning(
                                "An HTTP error occured ({} {}), retrying api_request()".format(
                                    e, result.text
                                )
                            )

                        # Retry request
                        time.sleep(1)
                        return self.api_request(
                            method, data, http, callback, raw, secure, retry=retry - 1
                        )

                    else:
                        error = NitroError(
                            "Error with method ({}) and data : {}. From requests.HTTPError {} {}".format(
                                method, data, e, result.text
                            )
                        )
                        log.error(error)
                        raise error from e

                else:  # The result is not an HTTP Error
                    response = result
                    result = self._unpack_resp(result)

                    if privateApiCall:
                        result = self._format_priv_resp(result)

                    if callback:
                        result = callback(result)

                    log.debug(
                        "{} -> Result ({}): {}".format(
                            str(response), type(result), str(result)[:200]
                        )
                    )

                    return result

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:

            if retry > 0:
                log.warning(
                    "An network error occured ({}), retrying api_request()".format(e)
                )
                time.sleep(1)
                return self.api_request(
                    method, data, http, callback, raw, secure, retry=retry - 1
                )
            else:
                raise e

        except requests.exceptions.TooManyRedirects as e:
            log.error(e)
            raise

    def esm_request(self, *args, **kwargs):
        """Same as `msiempy.core.session.NitroSession.api_request`"""
        return self.api_request(*args, **kwargs)

    def version(self):
        """
        Returns: `str` ESM short version.
        Example: '10.0.2'
        """
        return self.buildstamp().split()[0]

    def buildstamp(self):
        """
        Returns: `str` ESM buildstamp.
        Example: '10.0.2 20170516001031'
        """
        return self.request("build_stamp")["buildStamp"]

    def get_internal_file(self, file_token):
        """Uses the private API to retrieve, assemble and delete a temp file from the ESM.

        Arguments:

        - `file_token` (`str`): File token ID
        """
        pos = 0
        nbytes = 0
        resp = self.request("get_rfile2", ftoken=file_token, pos=pos, nbytes=nbytes)

        if resp["FSIZE"] == resp["BREAD"]:
            data = resp["DATA"]
            self.request("del_rfile", ftoken=file_token)
            return data

        data = []
        data.append(resp["DATA"])
        file_size = int(resp["FSIZE"])
        collected = int(resp["BREAD"])

        while file_size > collected:
            pos += int(resp["BREAD"])
            nbytes = file_size - collected
            resp = self.request("get_rfile2", ftoken=file_token, pos=pos, nbytes=nbytes)
            collected += int(resp["BREAD"])
            data.append(resp["DATA"])

        resp = self.request("del_rfile", ftoken=file_token)
        return "".join(data)

    def request(self, request, **kwargs):
        """
        Interface to make ESM API calls more simple by interpolating `**kwargs` arguments with `msiempy.core.session.NitroSession.PARAMS` docstrings and build a valid datastructure for the HTTP data.

        Then call the `msiempy.core.session.NitroSession.api_request` method with the built data.

        Also handles auto-login.

        Arguments:

        - `request`: Name keyword corresponding to the request name in `msiempy.core.session.NitroSession.PARAMS` mapping.
        - `http`: HTTP method.
        - `callback` : function to apply afterwards
        - `raw` : If true will return the Response object from requests module.
        - `secure` : If true will not log the content of the request.
        - `retry` : Number of time the request can be retried

        Interpolation parameters :

        - `**kwargs` : Interpolation parameters that will be match to `msiempy.core.session.NitroSession.PARAMS` templates. Dynamic keyword arguments.

        Returns:

        - a `dict`, `list` or `str` object
        - the `resquest.Response` object if raw=True
        - `result.text` if `requests.HTTPError`,
        - `None` if Timeout or TooManyRedirects if raw=False

        Exemple:

        ```python
        from msiempy import NitroSession
        s = NitroSession()
        s.login()
        # Get all last 24h alarms details
        alarms = s.request('get_alarms', time_range='LAST_24_HOURS',  status='', page_size=500, page_number=0)
        for a in alarms:
            a.update(s.request('get_notification_detail', id=a['id']))
        ```

        If you're reading this thom an IDE, all possible requests are listed on the documentation webpage:
        https://mfesiem.github.io/docs/msiempy/core/session.html#msiempy.core.session.NitroSession.request
        """

        log.debug(
            "Calling nitro request : {} kwargs={}".format(
                str(request),
                "***"
                if "secure" in kwargs and kwargs["secure"] == True
                else str(kwargs),
            )
        )

        method, data = self.PARAMS.get(request)

        if data != None:
            if isinstance(data, Template):
                data = data.substitute(**kwargs)
            data = ast.literal_eval(data.replace("\n", "").replace("\t", ""))

        if method != None and isinstance(method, Template):
            try:
                method = method.substitute(**kwargs)
            except TypeError as err:
                if "must be real number, not dict" in str(err):
                    log.warning(
                        "Interpolation failed probably because of the private API calls formatting... Unexpected behaviours can happend."
                    )

        if not self.logged_in and method != "login":
            # Autologin
            self.login()

        # Dynamically checking the esm_request arguments so additionnal parameters can be passed.
        esm_request_args = inspect.getfullargspec(self.api_request)[0]
        params = {}
        for arg in kwargs:
            if arg in esm_request_args:
                params[arg] = kwargs[arg]
        return self.api_request(method=method, data=data, **params)

    @staticmethod
    def _init_log(verbose=False, quiet=False, logfile=None):
        """
        Private method. Inits the session's logger settings based on params
        All objects should be able to log stuff, so the logger is globaly accessible
        """

        log = logging.getLogger("msiempy")

        log.setLevel(logging.DEBUG)

        std = logging.StreamHandler()
        std.setLevel(logging.DEBUG)
        std.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))

        if verbose:
            std.setLevel(logging.DEBUG)
        elif quiet:
            std.setLevel(logging.CRITICAL)
        else:
            std.setLevel(logging.INFO)

        log.handlers = []

        log.addHandler(std)

        if logfile:
            fh = logging.FileHandler(logfile)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
            log.addHandler(fh)

        if verbose and quiet:
            log.warning(
                "Verbose and quiet values are both set to True. By default, output will be verbose."
            )

        return log

    @staticmethod
    def _format_params(cmd, **params):
        """
        Format private API call.
        """
        params = {k: v for k, v in params.items() if v != None}
        params = "%14".join([k + "%13" + v + "%13" for (k, v) in params.items()])

        if params:
            params = "Request=API%13" + cmd + "%13%14" + params + "%14"
        else:
            params = "Request=API%13" + cmd + "%13%14"
        return params

    @staticmethod
    def _format_priv_resp(resp):
        """
        Format response from private API.
        """
        resp = re.search("Response=(.*)", resp).group(1)
        resp = resp.replace("%14", " ")
        pairs = resp.split()
        formatted = {}
        for pair in pairs:
            pair = pair.replace("%13", " ")
            pair = pair.split()
            key = pair[0]
            if key == "ITEMS":
                value = pair[-1]
            else:
                value = urllib.parse.unquote(pair[-1])
            formatted[key] = value
        return formatted

    @staticmethod
    def _unpack_resp(response):
        """Unpack data from response.
        Should not be necessary with API v2.
        Args:
            response: requests.Response response object
        Returns a list, a dict or a string
        """
        log.debug("Unpacking SIEM response: {}".format(str(response.text)[:200]))
        try:
            data = response.json()
            if isinstance(response.json(), dict):
                try:
                    data = data["value"]
                except KeyError:
                    try:
                        data = data["return"]
                    except KeyError:
                        pass

        except ValueError:
            data = response.text

        return data


# Dynamically document all PARAMS requests
_PARAMS_DOCS = ""
for k, v in _PARAMS.items():
    name = "{}".format(k)
    keywords = []
    params = ""
    endpoint = "{}".format(
        urlparse(v[0] if not isinstance(v[0], Template) else v[0].template).path
    )
    if isinstance(v[0], Template):
        keywords += [
            s[1] or s[2]
            for s in Template.pattern.findall(v[0].template)
            if s[1] or s[2]
        ]
    if isinstance(v[1], Template):
        keywords += [
            s[1] or s[2]
            for s in Template.pattern.findall(v[1].template)
            if s[1] or s[2]
        ]
    params = ", ".join(["{}".format(k) for k in keywords])
    _PARAMS_DOCS += "            request('{}', {}) # Call {}  \n".format(
        name, params, endpoint
    )

__pdoc__["NitroSession.request"] = (
    NitroSession.request.__doc__
    + """
        All requests:    
        ( *All upper cases method names signals to use the private API methods.* )  

"""
    + _PARAMS_DOCS
)


class NitroError(Exception):
    """
    Base ESM exception.
    It's used when the user/passwd is incorrect and other HTTP errors.
    """

    pass
