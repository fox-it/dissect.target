import datetime
import warnings
from typing import Iterator, List, Optional
from xml.etree.ElementTree import Element

from defusedxml import ElementTree
from dissect import cstruct
from dissect.cstruct.types.instance import Instance
from flow.record import GroupedRecord, RecordDescriptor
from flow.record.fieldtypes import path

from dissect.target.exceptions import InvalidTaskError, UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.target import Target

warnings.simplefilter(action="ignore", category=FutureWarning)

TaskRecord = TargetRecordDescriptor(
    "filesystem/windows/task",
    [
        ("path", "uri"),
        ("string", "security_descriptor"),
        ("string", "source"),
        ("datetime", "date"),
        ("string", "author"),
        ("string", "version"),
        ("string", "description"),
        ("string", "documentation"),
        ("string", "principal_id"),
        ("string", "user_id"),
        ("string", "logon_type"),
        ("string", "group_id"),
        ("string", "display_name"),
        ("string", "run_level"),
        ("string", "process_token_sid_type"),
        ("string", "required_privileges"),
        ("boolean", "allow_start_on_demand"),
        ("string", "restart_on_failure_interval"),
        ("string", "restart_on_failure_count"),
        ("string", "mutiple_instances_policy"),
        ("string", "dissalow_start_on_batteries"),
        ("string", "stop_going_on_batteries"),
        ("string", "allow_start_on_demand"),
        ("string", "start_when_available"),
        ("string", "network_profile_name"),
        ("string", "run_only_network_available"),
        ("string", "wake_to_run"),
        ("string", "enabled"),
        ("string", "hidden"),
        ("string", "delete_expired_task_after"),
        ("string", "idle_duration"),
        ("string", "idle_wait_timeout"),
        ("string", "idle_stop_on_idle_end"),
        ("string", "idle_restart_on_idle"),
        ("string", "network_settings_name"),
        ("string", "network_settings_id"),
        ("string", "execution_time_limit"),
        ("string", "priority"),
        ("string", "run_only_idle"),
        ("string", "unified_scheduling_engine"),
        ("string", "disallow_start_on_remote_app_session"),
        ("string", "data"),
    ],
)

ExecRecord = RecordDescriptor(
    "filesystem/windows/task/action/Exec",
    [
        ("string", "action_type"),
        ("string", "command"),
        ("string", "arguments"),
        ("string", "working_directory"),
    ],
)

ComHandlerRecord = RecordDescriptor(
    "filesystem/windows/task/action/ComHandler",
    [
        ("string", "action_type"),
        ("string", "class_id"),
        ("string", "data"),
    ],
)

SendEmailRecord = RecordDescriptor(
    "filesystem/windows/task/action/SendEmail",
    [
        ("string", "action_type"),
        ("string", "server"),
        ("string", "subject"),
        ("string", "to"),
        ("string", "cc"),
        ("string", "bcc"),
        ("string", "replyto"),
        ("string", "email_from"),
        ("string", "header_name"),
        ("string", "header_value"),
        ("string", "body"),
        ("string", "attachment"),
    ],
)

ShowMessageRecord = RecordDescriptor(
    "filesystem/windows/task/action/ShowMessage",
    [
        ("string", "tile"),
        ("string", "body"),
    ],
)

LogonTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/LogonTrigger",
    [
        ("string", "user_id"),
        ("string", "delay"),
    ],
)

BootTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/BootTrigger",
    [
        ("string", "delay"),
    ],
)

IdleTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/IdleTrigger",
    [],
)

TimeTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/TimeTrigger",
    [
        ("string", "random_delay"),
    ],
)

TriggerRecord = RecordDescriptor(
    "filesystem/windows/task/Trigger",
    [
        ("string", "enabled"),
        ("string", "start_boundary"),
        ("string", "end_boundary"),
        ("string", "repetition_interval"),
        ("string", "repetition_duration"),
        ("string", "repetition_stop_duration_end"),
        ("string", "execution_time_limit"),
    ],
)

EventTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/EventTrigger",
    [
        ("string", "subscription"),
        ("string", "delay"),
        ("string", "period_of_occurence"),
        ("string", "number_of_occurences"),
        ("string", "matching_elements"),
        ("string", "value_queries"),
    ],
)

SessionStateChangeTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/SessionStateChangeTrigger",
    [
        ("string", "user_id"),
        ("string", "delay"),
        ("string", "state_change"),
    ],
)

CalendarTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/CalendarTrigger",
    [
        ("string", "random_delay"),
        ("string", "schedule_by_day"),
        ("string", "schedule_by_week"),
        ("string", "schedule_by_month"),
        ("string", "schedule_by_day_of_week"),
    ],
)

DailyTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/DailyTrigger",
    [
        ("uint16", "days_between_triggers"),
        ("uint16[]", "unused"),
        ("uint16", "padding"),
        ("uint16", "reserved2"),
        ("uint16", "reserved3"),
    ],
)

WeeklyTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/WeeklyTrigger",
    [
        ("uint16", "weeks_between_triggers"),
        ("string[]", "days_of_week"),
        ("uint16[]", "unused"),
        ("uint16", "padding"),
        ("uint16", "reserved2"),
        ("uint16", "reserved3"),
    ],
)

MonthlyDateTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/MonthlyDateTrigger",
    [
        ("string", "day_of_month"),
        ("string[]", "months_of_year"),
        ("uint16", "padding"),
        ("uint16", "reserved2"),
        ("uint16", "reserved3"),
    ],
)

MonthlyDowTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/MonthlyDowTrigger",
    [
        ("string", "which_week"),
        ("string[]", "day_of_week"),
        ("string", "months_of_year"),
        ("uint16", "padding"),
        ("uint16", "reserved2"),
        ("uint16", "reserved3"),
    ],
)


c_atjob = """
    struct PRIORITY {
        uint32  undefined1: 5;          /* bit 31..27 */
        uint32  normal : 1;             /* bit 26 - NORMAL_PRIORITY_CLASS */
        uint32  idle : 1;               /* bit 25 - IDLE_PRIORITY_CLASS */
        uint32  high : 1;               /* bit 24 - HIGH_PRIORITY_CLASS */
        uint32  realtime : 1;           /* bit 23 - REALTIME_PRIORITY_CLASS */
        uint32  undefined2 : 23;        /* bit 22..0 */
    };

    struct FLAGS {
        uint32  interactive : 1;        /* bit 31 - can interact with user. */
        uint32  delete_when_done : 1;   /* bit 30 - delete task when done. */
        uint32  disabled : 1;           /* bit 29 - task is disabled. */
        uint32  undefined3 : 1;         /* bit 28 */
        uint32  only_idle : 1;          /* bit 27 - only start when idle. */
        uint32  stop_on_idle_end : 1;   /* bit 26 - stop when no longer idle. */
        uint32  disallow_battery : 1;   /* bit 25 - don't start when on batteries. */
        uint32  stop_battery : 1;       /* bit 24 - stop when going to batteries. */
        uint32  docked : 1;             /* bit 23 - should be 0, unused. */
        uint32  hidden : 1;             /* bit 22 - hidden task. */
        uint32  internet_connected : 1; /* bit 21 - should be 0, unused. */
        uint32  restart_on_idle: 1;     /* bit 20 - restart task when returning to idle state. */
        uint32  wake_to_run : 1;        /* bit 19 - can resume or wake the system to run. */
        uint32  logged_on_only : 1;     /* bit 18 - only runs when specified user is logged on. */
        uint32  undefined2 : 10;        /* bit 8..17 */
        uint32  task_app_name_set : 1;  /* bit 7 - has app name. */
        uint32  undefined1 : 7;         /* bit 0..6 */
    };

    struct HRESULT {
        uint32  severity : 1;           /* 0 = success, 1 = failure. */
        uint32  reserved_value : 4;     /* reserved value */
        uint32  facility_code : 11;     /* responsibility for the error or warning. */
        uint32  return_code : 16;       /* error code that describes the error or warning. */
    };

    struct TFLAGS {
        uint32  has_end_date : 1;       /* bit 31 - stop at some point in time. */
        uint32  kill_at_end : 1;        /* bit 30 - stop at end of repetition period. */
        uint32  trigger_disabled : 1;   /* bit 29 - trigger is disabled. */
        uint32  unused : 29;            /* bit 28..0 - should be 0. */
    };

    struct TRIGGER {
        uint16  trigger_size;           /* trigger size, should be 0x0030. */
        uint16  reserved1;              /* reserved. */
        uint16  begin_year;             /* first trigger fire date, year. */
        uint16  begin_month;            /* first trigger fire date, month. */
        uint16  begin_day;              /* first trigger fire date, day. */
        uint16  end_year;               /* last trigger fire date, year. */
        uint16  end_month;              /* last trigger fire date, month. */
        uint16  end_day;                /* last trigger fire date, day. */
        uint16  start_hour;             /* hour of trigger fire. */
        uint16  start_minute;           /* minute of trigger fire. */
        uint32  minutes_duration;       /* task runs for duration in minutes. */
        uint32  minutes_interval;       /* task runs every interval in minutes. */
        TFLAGS  trigger_flags;          /* task trigger bit flags. */
        uint32  trigger_type;           /* trigger type. */
        uint16  trigger_specific0;      /* value specific to trigger type. */
        uint16  trigger_specific1;      /* value specific to trigger type. */
        uint16  trigger_specific2;      /* value specific to trigger type. */
        uint16  padding;                /* should be 0. */
        uint16  reserved2;              /* should be 0. */
        uint16  reserved3;              /* should be 0. */
    };

    struct ATJOB_DATA {
        uint16      windows_version;                    /* 0x00 - windows version that generated this task. */
        uint16      file_version;                       /* 0x02 - should be set to 1. */
        char        uuid[16];                           /* 0x04 - randomly generated UUID. */
        uint16      app_name_len_offset;                /* 0x14 - offset in bytes to app_name_len. */
        uint16      triggers_offset;                    /* 0x16 - offset in bytes to triggers. */
        uint16      retry_count;                        /* 0x18 - number of attempts to retry when failing. */
        uint16      retry_interval;                     /* 0x1a - minutes between retries. */
        uint16      idle_deadline;                      /* 0x1c - minutes to wait for idle machine. */
        uint16      idle_wait;                          /* 0x1e - minutes of idle before run task. */
        PRIORITY    task_prio;                          /* 0x20 - bit flags with max. one bit set. */
        uint32      max_run_time;                       /* 0x24 - milliseconds to wait for task complete. */
        uint32      exit_code;                          /* 0x28 - should be set to 0x00000000. */
        uint32      status;                             /* 0x2C - status value of the task. */
        FLAGS       task_flags;                         /* 0x30 - task flag bits. */
        uint16      last_year;                          /* 0x34 - last run year. */
        uint16      last_month;                         /* 0x36 - last run month. */
        uint16      last_weekday;                       /* 0x38 - last run weekday. */
        uint16      last_day;                           /* 0x3a - last run day of the month. */
        uint16      last_hour;                          /* 0x3c - last run hour (24h). */
        uint16      last_minute;                        /* 0x3e - last run minute. */
        uint16      last_second;                        /* 0x40 - last run second. */
        uint16      last_millisecond;                   /* 0x42 - last run millisecond. */
        uint16      running_instances;                  /* 0x44 - number of currently running instances. */
        uint16      app_name_len;                       /* 0x46 - app name character count. */
        char        app_name[app_name_len * 2];         /* 0x48 - app name - null-terminated Unicode string. */
        uint16      par_char_count;                     /*      - parameters character count. */
        char        parameters[par_char_count * 2];     /*      - parameters - null-terminated Unicode string. */
        uint16      dir_char_count;                     /*      - working dir character count. */
        char        working_dir[dir_char_count * 2];    /*      - working dir - null-terminated Unicode string. */
        uint16      author_char_count;                  /*      - author character count. */
        char        author[author_char_count * 2];      /*      - author - null-terminated Unicode string. */
        uint16      comment_char_count;                 /*      - comment character count. */
        char        comment[comment_char_count * 2];    /*      - comment - null-terminated Unicode string. */
        uint16      user_data_size;                     /*      - user data size in bytes. */
        uint8       user_data[user_data_size];          /*      - arbitrary bits, implementation specific. */
        uint16      reserved_data_size;                 /*      - should be 0 or 8. */
        HRESULT     reserved_hresult;                   /*      - used to describe an error. */
        uint32      reserved_task_flags;                /*      - not used, should be zero. */
        uint16      trigger_count;                      /*      - size in bytes of array of triggers. */
        TRIGGER     task_triggers[trigger_count];       /*      - an arry of zero or more triggers. */
//      uint16      s_ver;                              /*      - SignatureVersion, should be 1. */
//      uint16      c_ver;                              /*      - MinClientVersion, should be 1. */
//      uint8       job_signature[64 * s_ver * c_ver];  /*      - calculated job signature. */
    };
    """
atjob = cstruct.cstruct()
atjob.load(c_atjob)


def strip_namespace(data):
    if data.tag.startswith("{"):
        ns_length = data.tag.find("}")
        ns = data.tag[0 : ns_length + 1]
        for element in data.iter():
            if element.tag.startswith(ns):
                element.tag = element.tag[len(ns) :]
    return data


def minutes_duration_to_iso(minutes: int) -> Optional[str]:
    """
    Convert the given number of minutes to an ISO 8601 duration format string, like those found in the xml tasks.
    The most significant unit is days (D), the least significant is minutes (M).

    Args:
        minutes: The number of minutes to convert.

    Returns:
        An ISO 8601 duration format string representing the given number of minutes,
        or `None` if the number of minutes is zero.

    Raises:
        TypeError: If the minutes argument is not an integer.
    """
    if not isinstance(minutes, int):
        raise TypeError("Expected an integer for the minutes argument")

    if minutes == 0:
        return None
    else:
        # Calculate the number of days, hours, and minutes
        days, minutes = divmod(minutes, 1440)
        hours, minutes = divmod(minutes, 60)

        # Build the ISO duration format string
        duration_iso = "P" if days == 0 else f"P{days}D"
        duration_iso += "T" if hours or minutes else ""
        duration_iso += f"{hours}H" if hours != 0 else ""
        duration_iso += f"{minutes}M" if minutes != 0 else ""

        return duration_iso


def get_flags_data(flags: int, items: List[str]) -> List[str]:
    """
    Create a generator of items corresponding to the flags.

    Args:
        flags: An integer representing the trigger specific flags.
        items: A list of items corresponding to the flags.

    Yields:
        Each item based on the flags.
    """
    flags_binary = bin(flags)[2:]  # Convert to binary and remove "0b"
    for i, char in enumerate(flags_binary[::-1]):
        if char == "1":
            yield items[i]


def get_months_of_year(flags: int) -> List[str]:
    """
    Convert 16-bit flags to a list of months of the year.

    Args:
        flags: An integer representing the trigger specific flags. See also:
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/5ba70e9b-c0f1-49f6-9aae-b52231346108

    Returns:
        A list of months as strings.
    """
    months = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    return list(get_flags_data(flags, months))


def get_days_of_week(flags: int) -> List[str]:
    """
    Get the list of weekdays corresponding to the given trigger specific 16-bit flags.

    Args:
        flags: An integer representing the trigger specific flags. See also:
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/b7a0fc39-b43a-435a-9f37-60e48f340b9b

    Returns:
        A list of weekdays as strings.
    """
    weekdays = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ]
    return list(get_flags_data(flags, weekdays))


class AtTask:
    def __init__(self, at_data: Instance) -> None:
        """
        Initialize the class for opening .job task files created by at.exe.

        Args:
            at_data: cstruct instance of an .job file.
        """
        self.at_data = at_data

    def get_at_actions(self) -> Iterator[TargetRecordDescriptor]:
        """
        Get the at job task actions.

        Yields:
            An iterator of at job task actions.
        """
        action_type = "Exec"
        command = self.at_data.app_name.decode("utf-16-le").rstrip("\x00")
        args = self.at_data.parameters.decode("utf-16-le").rstrip("\x00")
        wrkdir = self.at_data.working_dir.decode("utf-16-le").rstrip("\x00")

        yield ExecRecord(
            action_type=action_type,
            command=command,
            arguments=args,
            working_directory=wrkdir,
        )

    def get_at_triggers(self) -> Iterator[GroupedRecord]:
        """
        Get the job task triggers.

        Yields:
            An iterator of at job task triggers.
        """
        TRIGGER_TYPE_NAMES = {
            0: "ONCE",
            1: "DAILY",
            2: "WEEKLY",
            3: "MONTHLYDATE",
            4: "MONTHLYDOW",
            5: "EVENT_ON_IDLE",
            6: "EVENT_AT_SYSTEMSTART",
            7: "EVENT_AT_LOGON",
        }
        for trigger in self.at_data.task_triggers:
            trigger_type = TRIGGER_TYPE_NAMES.get(trigger.trigger_type, None)
            enabled = False if trigger.trigger_flags.trigger_disabled else True

            s_year = trigger.begin_year
            s_month = trigger.begin_month
            s_day = trigger.begin_day
            start_boundary = datetime.datetime(year=s_year, month=s_month, day=s_day).date().isoformat()

            e_year = trigger.end_year
            e_month = trigger.end_month
            e_day = trigger.end_day
            end_boundary = None
            if trigger.trigger_flags.has_end_date:
                end_boundary = datetime.datetime(year=e_year, month=e_month, day=e_day).date().isoformat()

            repetition_interval = minutes_duration_to_iso(trigger.minutes_interval)
            repetition_duration = minutes_duration_to_iso(trigger.minutes_duration)
            repetition_stop_duration_end = True if trigger.trigger_flags.kill_at_end == 1 else False
            execution_time_limit = self.at_data.max_run_time  # This one is already converted to ISO

            base = TriggerRecord(
                enabled=enabled,
                start_boundary=start_boundary,
                end_boundary=end_boundary,
                repetition_interval=repetition_interval,
                repetition_duration=repetition_duration,
                repetition_stop_duration_end=repetition_stop_duration_end,
                execution_time_limit=execution_time_limit,
            )

            padding = trigger.padding
            reserved2 = trigger.reserved2
            reserved3 = trigger.reserved3

            if trigger_type == "EVENT_AT_LOGON":
                # No trigger specific flags in job files for this trigger type
                pass

            if trigger_type == "EVENT_AT_SYSTEMSTART":
                # No trigger specific flags in job files for this trigger type
                pass

            if trigger_type == "EVENT_ON_IDLE":
                # No trigger specific flags in job files for this trigger type
                pass

            if trigger_type == "ONCE":
                # No trigger specific flags in job files for this trigger type
                pass

            if trigger_type == "DAILY":
                interval = trigger.trigger_specific0
                unused = [trigger.trigger_specific1, trigger.trigger_specific2]

                record = DailyTriggerRecord(
                    days_between_triggers=interval,
                    unused=unused,
                    padding=padding,
                    reserved2=reserved2,
                    reserved3=reserved3,
                )

                yield GroupedRecord("filesystem/windows/task/DailyTrigger", [base, record])

            if trigger_type == "WEEKLY":
                interval = trigger.trigger_specific0

                # Find weekdays corresponding with trigger specific flags
                days_of_week = get_days_of_week(trigger.trigger_specific1)
                unused = [trigger.trigger_specific2]

                record = WeeklyTriggerRecord(
                    weeks_between_triggers=interval,
                    days_of_week=days_of_week,
                    unused=unused,
                    padding=padding,
                    reserved2=reserved2,
                    reserved3=reserved3,
                )

                yield GroupedRecord("filesystem/windows/task/WeeklyTrigger", [base, record])

            if trigger_type == "MONTHLYDATE":
                # Convert trigger_specific fields to binary, remove the "0b" prefix, and pad with zeroes to 16 digits
                day_flag_part1 = bin(trigger.trigger_specific0)[2:].zfill(16)
                day_flag_part2 = bin(trigger.trigger_specific1)[2:].zfill(16)
                # Concatenate the two binary strings to form the complete day_flag
                day_of_month_flag = day_flag_part2 + day_flag_part1
                # Reverse the day_flag string (LE), find the index of "1", add 1 to get the day of the month
                day_of_month = day_of_month_flag[::-1].index("1") + 1

                # Find months corresponding with trigger specific flags
                months_of_year = get_months_of_year(trigger.trigger_specific2)

                record = MonthlyDateTriggerRecord(
                    day_of_month=day_of_month,
                    months_of_year=months_of_year,
                    padding=padding,
                    reserved2=reserved2,
                    reserved3=reserved3,
                )

                yield GroupedRecord("filesystem/windows/task/MonthlyDateTrigger", [base, record])

            if trigger_type == "MONTHLYDOW":
                week = trigger.trigger_specific0
                week_strings = [
                    "FIRST_WEEK",
                    "SECOND_WEEK",
                    "THIRD_WEEK",
                    "FOURTH_WEEK",
                    "LAST_WEEK",
                ]
                week = week_strings[week - 1]
                day = get_days_of_week(trigger.trigger_specific1)
                months = get_months_of_year(trigger.trigger_specific2)
                record = MonthlyDowTriggerRecord(
                    which_week=week,
                    day_of_week=day,
                    months_of_year=months,
                    padding=padding,
                    reserved2=reserved2,
                    reserved3=reserved3,
                )

                yield GroupedRecord("filesystem/windows/task/MonthlyDowTrigger", [base, record])


class XmlTask:
    def __init__(self, xml_data) -> None:
        """
        Initialize the XmlTask class for open XML-based task files.

        Args:
            xml_data (ElementTree.Element): The XML data representing the task.
        """
        self.xml_data = xml_data

    def get_element(self, xml_path: str, xml_data: Element = None) -> str:
        """
        Get the value of the specified XML element.

        Args:
            path (str): The string used to locate the element.
            xml_data (ElementTree.Element, optional): The XML data to search in. If not provided, use self.xml_data.

        Returns:
            str: The value of the XML element if found, otherwise None.
        """
        xml_data = xml_data or self.xml_data
        try:
            return xml_data.find(xml_path).text
        except AttributeError:
            return

    def get_raw(self, xml_path: str) -> str:
        """
        Get the raw XML data of the specified element.

        Args:
            path (str): The string used to locate the element.

        Returns:
            bytes: The raw XML data as string of the element if found, otherwise None.
        """
        data = self.xml_data.find(xml_path)
        if data:
            return ElementTree.tostring(data, encoding="utf-8")

    def get_triggers(self) -> Iterator[GroupedRecord]:
        """
        Get the triggers from the XML task data.

        Yields:
            GroupedRecord: The grouped record representing a trigger.
        """
        for trigger in self.xml_data.findall("Triggers/*"):
            trigger_type = trigger.tag
            enabled = self.get_element("Enabled", trigger)
            start_boundary = self.get_element("StartBoundary", trigger)
            end_boundary = self.get_element("EndBoundary", trigger)
            repetition_interval = self.get_element("Repetition/Interval", trigger)
            repetition_duration = self.get_element("Repetition/Duration", trigger)
            repetition_stop_duration_end = self.get_element("Repetition/StopAtDurationEnd", trigger)
            execution_time_limit = self.get_element("ExecutionTimeLimit", trigger)

            base = TriggerRecord(
                enabled=enabled,
                start_boundary=start_boundary,
                end_boundary=end_boundary,
                repetition_interval=repetition_interval,
                repetition_duration=repetition_duration,
                repetition_stop_duration_end=repetition_stop_duration_end,
                execution_time_limit=execution_time_limit,
            )

            if trigger_type == "LogonTrigger":
                user_id = self.get_element("UserId", trigger)
                delay = self.get_element("UserId", trigger)
                record = LogonTriggerRecord(
                    user_id=user_id,
                    delay=delay,
                )
                yield GroupedRecord("filesystem/windows/task/LogonTrigger", [base, record])

            if trigger_type == "BootTrigger":
                delay = self.get_element("Delay", trigger)
                record = BootTriggerRecord(delay=delay)
                yield GroupedRecord("filesystem/windows/task/BootTrigger", [base, record])

            if trigger_type == "IdleTrigger":
                pass  # No extra fields

            if trigger_type == "TimeTrigger":
                random_delay = self.get_element("RandomDelay", trigger)

                record = TimeTriggerRecord(random_delay=random_delay)
                yield GroupedRecord("filesystem/windows/task/TimeTrigger", [base, record])

            if trigger_type == "EventTrigger":
                subscription = self.get_element("Subscription", trigger)
                delay = self.get_element("Delay", trigger)
                period_of_occurence = self.get_element("PeriodOfOccurrence", trigger)
                number_of_occurences = self.get_element("NumberOfOccurences", trigger)
                matching_elements = self.get_element("MatchingElement", trigger)
                value_queries = self.get_element("ValueQueries/Value", trigger)

                record = EventTriggerRecord(
                    subscription=subscription,
                    delay=delay,
                    period_of_occurence=period_of_occurence,
                    number_of_occurences=number_of_occurences,
                    matching_elements=matching_elements,
                    value_queries=value_queries,
                )

                yield GroupedRecord("filesystem/windows/task/EventTrigger", [base, record])

            if trigger_type == "SessionStateChangeTrigger":
                user_id = self.get_element("UserId", trigger)
                delay = self.get_element("Delay", trigger)
                state_change = self.get_element("StateChange", trigger)

                record = SessionStateChangeTriggerRecord(
                    user_id=user_id,
                    delay=delay,
                    state_change=state_change,
                )

                yield GroupedRecord("filesystem/windows/task/SessionStateTrigger", [base, record])

            if trigger_type == "CalendarTrigger":
                pass

    def get_actions(self) -> Iterator[RecordDescriptor]:
        """
        Get the actions from the XML task data.

        Yields:
            ActionRecord: The action record representing an action.
        """
        for action in self.xml_data.findall("Actions/*"):
            action_type = action.tag
            if action_type == "Exec":
                command = self.get_element("Actions/Exec/Command")
                args = self.get_element("Actions/Exec/Arguments")
                wrkdir = self.get_element("Actions/Exec/WorkingDirectory")
                yield ExecRecord(
                    action_type=action_type,
                    command=command,
                    arguments=args,
                    working_directory=wrkdir,
                )

            if action_type == "ComHandler":
                com_class_id = self.get_element("Actions/ComHandler/ClassId")
                com_data = self.get_raw("Actions/ComHandler/Data")
                yield ComHandlerRecord(
                    action_type=action_type,
                    class_id=com_class_id,
                    data=com_data,
                )

            if action_type == "SendEmail":
                email_server = self.get_element("Actions/ShowMessage/Server")
                email_subject = self.get_element("Actions/ShowMessage/Subject")
                email_to = self.get_element("Actions/ShowMessage/To")
                email_cc = self.get_element("Actions/ShowMessage/Cc")
                email_bcc = self.get_element("Actions/ShowMessage/Bcc")
                email_reply_to = self.get_element("Actions/ShowMessage/ReplyTo")
                email_from = self.get_element("Actions/ShowMessage/From")
                email_body = self.get_element("Actions/ShowMessage/Body")
                email_attachments = self.get_element("Actions/ShowMessage/Attachments/File")
                email_headers_name = self.get_element("Actions/ShowMessage/Headers/HeadersField/Name")
                email_headers_value = self.get_element("Actions/ShowMessage/Headers/headersField/Value")
                yield SendEmailRecord(
                    action_type=action_type,
                    server=email_server,
                    subject=email_subject,
                    to=email_to,
                    cc=email_cc,
                    bcc=email_bcc,
                    replyto=email_reply_to,
                    email_from=email_from,
                    header_name=email_headers_name,
                    header_value=email_headers_value,
                    body=email_body,
                    attachment=email_attachments,
                )

            if action_type == "ShowMessage":
                title = self.get_element("Actions/ShowMessage/Title")
                body = self.get_element("Actions/ShowMessage/Body")
                yield ShowMessageRecord(
                    action_type=action,
                    title=title,
                    body=body,
                )


class TasksPlugin(Plugin):
    """
    Plugin for retrieving scheduled tasks on a Windows system.
    """

    PATHS = [
        "sysvol/windows/system32/tasks",
        "sysvol/windows/system32/tasks_migrated",
        "sysvol/windows/syswow64/tasks",
        "sysvol/windows/tasks",  # at.exe job file location
    ]

    def __init__(self, target: Target):
        """
        Initialize the TasksPlugin and build a list with files to parse.

        Args:
            target: The target system.
        """
        super().__init__(target)
        self.task_files = []

        for file_path in self.PATHS:
            fpath = self.target.fs.path(file_path)
            if not fpath.exists():
                continue

            for entry in fpath.rglob("*"):
                if entry.is_file() and (not entry.suffix or entry.suffix.lower() == ".job"):
                    self.task_files.append(entry)

    def check_compatible(self):
        if len(self.task_files) == 0:
            raise UnsupportedPluginError("No task files")

    @export(record=DynamicDescriptor(["path", "datetime"]))
    def tasks(self) -> Iterator:
        """
        Return all scheduled tasks on a Windows system.

        On a Windows system, a scheduled task is a program or script that is executed on a specific time or at specific
        intervals. An adversary may leverage such scheduled tasks to gain persistence on a system.

        References:
            https://en.wikipedia.org/wiki/Windows_Task_Scheduler

        Yields:
            TaskRecord or GroupedRecord: The scheduled tasks found on the target.
        """
        for task_file in self.task_files:
            try:
                if not task_file.suffix:
                    # try to open file as xml
                    for entry in self.parse_xml_task(task_file):
                        yield entry

                else:
                    # try open file as binary
                    for entry in self.parse_atjob(task_file):
                        yield entry
            except Exception as e:
                self.target.log.warning("An error occured parsing task %s: %s", task_file, str(e))
                self.target.log.debug("", exc_info=e)

    def parse_xml_task(self, entry: TargetPath) -> Iterator:
        """
        Parse a scheduled task from an XML file.

        Args:
            entry: The path to the XML task file.

        Yields:
            TaskRecord or GroupedRecord: The parsed scheduled task.
        """
        try:
            task_xml = strip_namespace(ElementTree.fromstring(entry.open().read(), forbid_dtd=True))
            task = XmlTask(task_xml)
        except Exception as e:
            raise InvalidTaskError(e)

        task.hostname = self.target.hostname
        task.uri = task.get_element("RegistrationInfo/URI")
        task.security_descriptor = task.get_element("RegistrationInfo/SecurityDescriptor")
        task.source = task.get_element("RegistrationInfo/Source")
        task.date = task.get_element("RegistrationInfo/Date")
        task.author = task.get_element("RegistrationInfo/Author")
        task.version = task.get_element("RegistrationInfo/Version")
        task.description = task.get_element("RegistrationInfo/Description")
        task.documentation = task.get_element("RegistrationInfo/Documentation")

        # Principals
        task.principal_id = task_xml.find("Principals/Principal").get("id")
        task.user_id = task.get_element("Principals/Principal/UserId")
        task.logon_type = task.get_element("Principals/Principal/LogonType")
        task.group_id = task.get_element("Principals/Principal/GroupId")
        task.display_name = task.get_element("Principals/Principal/DisplayName")
        task.run_level = task.get_element("Principals/Principal/RunLevel")
        task.process_token_sid_type = task.get_element("Principals/Principal/ProcessTokenSidType")
        task.required_privileges = task.get_element("Principals/Principal/RequiredPrivileges")

        # Settings
        task.allow_start_on_demand = task.get_element("Settings/AllowStartOnDemand")
        task.restart_on_failure_interval = task.get_element("Settings/RestartOnFailure/Interval")
        task.restart_on_failure_count = task.get_element("Settings/RestartOnFailure/Count")
        task.mutiple_instances_policy = task.get_element("Settings/MultipleInstancesPolicy")
        task.dissalow_start_on_batteries = task.get_element("Settings/DisallowStartIfOnBatteries")
        task.stop_going_on_batteries = task.get_element("Settings/StopIfGoingOnBatteries")
        task.allow_hard_terminate = task.get_element("Settings/AllowHardTerminate")
        task.start_when_available = task.get_element("Settings/StartWhenAvailable")
        task.network_profile_name = task.get_element("Settings/NetworkProfileName")
        task.run_only_network_available = task.get_element("Settings/RunOnlyIfNetworkAvailable")
        task.wake_to_run = task.get_element("Settings/WakeToRun")
        task.enabled = task.get_element("Settings/Enabled")
        task.hidden = task.get_element("Settings/Hidden")
        task.delete_expired_task_after = task.get_element("Settings/DeleteExpiredTaskAfter")
        task.idle_duration = task.get_element("Settings/IdleSettings/Duration")
        task.idle_wait_timeout = task.get_element("Settings/IdleSettings/WaitTimeout")
        task.idle_stop_on_idle_end = task.get_element("Settings/IdleSettings/StopOnIdleEnd")
        task.idle_restart_on_idle = task.get_element("Settings/IdleSettings/RestartOnIdle")
        task.network_settings_name = task.get_element("Settings/NetworkSettings/Name")
        task.network_settings_id = task.get_element("Settings/NetworkSettings/Id")
        task.execution_time_limit = task.get_element("Settings/ExecutionTimeLimit")
        task.priority = task.get_element("Settings/Priority")
        task.run_only_idle = task.get_element("Settings/RunOnlyIfIdle")
        task.unified_scheduling_engine = task.get_element("Settings/UseUnifiedSchedulingEngine")
        task.disallow_start_on_remote_app_session = task.get_element("Settings/DisallowStartOnRemoteAppSession")

        # Data
        task.data = task.get_raw("Data")

        record = TaskRecord(
            uri=path.from_windows(task.uri) if task.uri else None,
            security_descriptor=task.security_descriptor,
            source=task.source,
            date=task.date,
            author=task.author,
            version=task.version,
            description=task.description,
            documentation=task.documentation,
            principal_id=task.principal_id,
            user_id=task.user_id,
            logon_type=task.logon_type,
            display_name=task.display_name,
            run_level=task.run_level,
            process_token_sid_type=task.process_token_sid_type,
            required_privileges=task.required_privileges,
            allow_start_on_demand=task.allow_start_on_demand,
            restart_on_failure_interval=task.restart_on_failure_interval,
            restart_on_failure_count=task.restart_on_failure_count,
            mutiple_instances_policy=task.mutiple_instances_policy,
            dissalow_start_on_batteries=task.dissalow_start_on_batteries,
            stop_going_on_batteries=task.stop_going_on_batteries,
            start_when_available=task.start_when_available,
            network_profile_name=task.network_profile_name,
            run_only_network_available=task.run_only_network_available,
            wake_to_run=task.wake_to_run,
            enabled=task.enabled,
            hidden=task.hidden,
            delete_expired_task_after=task.delete_expired_task_after,
            idle_duration=task.idle_duration,
            idle_wait_timeout=task.idle_wait_timeout,
            idle_stop_on_idle_end=task.idle_stop_on_idle_end,
            idle_restart_on_idle=task.idle_restart_on_idle,
            network_settings_name=task.network_settings_name,
            network_settings_id=task.network_settings_id,
            execution_time_limit=task.execution_time_limit,
            priority=task.priority,
            run_only_idle=task.run_only_idle,
            unified_scheduling_engine=task.unified_scheduling_engine,
            disallow_start_on_remote_app_session=task.disallow_start_on_remote_app_session,
            data=task.data,
            _target=self.target,
        )

        yield record  # Without groups

        # Actions
        for entry in task.get_actions():
            grouped = GroupedRecord("filesystem/windows/task/grouped", [record, entry])
            yield grouped

        # Triggers
        for entry in task.get_triggers():
            grouped = GroupedRecord("filesystem/windows/task/grouped", [record, entry])
            yield grouped

    def parse_atjob(self, entry: TargetPath) -> Iterator[TargetRecordDescriptor]:
        """
        Parse a scheduled task from an at.exe job file.

        Args:
            entry: The path to the job file.

        Yields:
            TaskRecord or GroupedRecord: The parsed at.exe job file.
        """
        try:
            at_task_data = atjob.ATJOB_DATA(entry.open())
            at_task = AtTask(at_task_data)
        except Exception as e:
            raise InvalidTaskError(e)

        at_task_data.author = at_task_data.author.decode("utf-16-le").rstrip("\x00")
        at_task_data.comment = at_task_data.comment.decode("utf-16-le").rstrip("\x00")
        at_task_data.retry_interval = minutes_duration_to_iso(at_task_data.retry_interval)
        at_task_data.task_flags.disallow_battery = True if at_task_data.task_flags.disallow_battery else False
        at_task_data.task_flags.stop_battery = True if at_task_data.task_flags.stop_battery else False
        at_task_data.task_flags.internet_connected = True if at_task_data.task_flags.internet_connected else False
        at_task_data.task_flags.wake_to_run = True if at_task_data.task_flags.wake_to_run else False
        at_task_data.task_flags.hidden = True if at_task_data.task_flags.hidden else False
        task_enabled = False if at_task_data.task_flags.disabled else True
        at_task_data.idle_wait = minutes_duration_to_iso(at_task_data.idle_wait)
        at_task_data.idle_deadline = minutes_duration_to_iso(at_task_data.idle_deadline)
        at_task_data.task_flags.stop_on_idle_end = True if at_task_data.task_flags.stop_on_idle_end else False
        at_task_data.task_flags.restart_on_idle = True if at_task_data.task_flags.restart_on_idle else False
        at_task_data.max_run_time = round(at_task_data.max_run_time / 60000)
        at_task_data.max_run_time = minutes_duration_to_iso(at_task_data.max_run_time)
        at_task_data.task_flags.only_idle = True if at_task_data.task_flags.only_idle else False

        # check which prio bit is set
        for key, value in at_task_data.task_prio._values.items():
            if value:
                task_priority = key

        record = TaskRecord(
            uri=None,
            security_descriptor=None,
            source=entry,
            date=None,
            author=at_task_data.author,
            version=at_task_data.file_version,
            description=at_task_data.comment,
            documentation=None,
            principal_id=None,
            user_id=None,
            logon_type=None,
            display_name=None,
            run_level=None,
            process_token_sid_type=None,
            required_privileges=None,
            allow_start_on_demand=None,
            restart_on_failure_interval=at_task_data.retry_interval,
            restart_on_failure_count=at_task_data.retry_count,
            mutiple_instances_policy=None,
            dissalow_start_on_batteries=at_task_data.task_flags.disallow_battery,
            stop_going_on_batteries=at_task_data.task_flags.stop_battery,
            start_when_available=None,
            network_profile_name=None,
            run_only_network_available=at_task_data.task_flags.internet_connected,
            wake_to_run=at_task_data.task_flags.wake_to_run,
            enabled=task_enabled,
            hidden=at_task_data.task_flags.hidden,
            delete_expired_task_after=None,
            idle_duration=at_task_data.idle_wait,
            idle_wait_timeout=at_task_data.idle_deadline,
            idle_stop_on_idle_end=at_task_data.task_flags.stop_on_idle_end,
            idle_restart_on_idle=at_task_data.task_flags.restart_on_idle,
            network_settings_name=None,
            network_settings_id=None,
            execution_time_limit=at_task_data.max_run_time,
            priority=task_priority,
            run_only_idle=at_task_data.task_flags.only_idle,
            unified_scheduling_engine=None,
            disallow_start_on_remote_app_session=None,
            data=at_task_data.user_data,
            _target=self.target,
        )

        yield record

        # Actions
        for entry in at_task.get_at_actions():
            grouped = GroupedRecord("filesystem/windows/task/grouped", [record, entry])
            yield grouped

        # Triggers
        for entry in at_task.get_at_triggers():
            grouped = GroupedRecord("filesystem/windows/task/grouped", [record, entry])
            yield grouped
