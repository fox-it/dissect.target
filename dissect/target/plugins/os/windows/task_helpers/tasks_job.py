import datetime
import warnings
from typing import Iterator, Optional

from dissect import cstruct
from flow.record import GroupedRecord

from dissect.target.exceptions import InvalidTaskError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugins.os.windows.task_helpers.tasks_records import (
    DailyTriggerRecord,
    ExecRecord,
    MonthlyDateTriggerRecord,
    MonthlyDowTriggerRecord,
    PaddingTriggerRecord,
    TriggerRecord,
    WeeklyTriggerRecord,
)
from dissect.target.target import Target

warnings.simplefilter(action="ignore", category=FutureWarning)

atjob_def = """
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
    wchar       app_name[app_name_len];             /* 0x48 - app name - null-terminated Unicode string. */
    uint16      par_char_count;                     /*      - parameters character count. */
    wchar       parameters[par_char_count];         /*      - parameters - null-terminated Unicode string. */
    uint16      dir_char_count;                     /*      - working dir character count. */
    wchar       working_dir[dir_char_count];        /*      - working dir - null-terminated Unicode string. */
    uint16      author_char_count;                  /*      - author character count. */
    wchar       author[author_char_count];          /*      - author - null-terminated Unicode string. */
    uint16      comment_char_count;                 /*      - comment character count. */
    wchar       comment[comment_char_count];        /*      - comment - null-terminated Unicode string. */
    uint16      user_data_size;                     /*      - user data size in bytes. */
    uint8       user_data[user_data_size];          /*      - arbitrary bits, implementation specific. */
    uint16      reserved_data_size;                 /*      - should be 0 or 8. */
    HRESULT     reserved_hresult;                   /*      - used to describe an error. */
    uint32      reserved_task_flags;                /*      - not used, should be zero. */
    uint16      trigger_count;                      /*      - size in bytes of array of triggers. */
    TRIGGER     task_triggers[trigger_count];       /*      - an arry of zero or more triggers. */
//      The following are optional fields and currently not parsed:
//      uint16      s_ver;                              /*      - SignatureVersion, should be 1. */
//      uint16      c_ver;                              /*      - MinClientVersion, should be 1. */
//      uint8       job_signature[64 * s_ver * c_ver];  /*      - calculated job signature. */
};
"""
atjob = cstruct.cstruct()
atjob.load(atjob_def)


class AtTask:
    """Initialize the class for opening .job task files created by at.exe.

    Args:
        job_file: the file to be parsed.
        target: the target system.
    """

    def __init__(self, job_file: TargetPath, target: Target):
        try:
            self.at_data = atjob.ATJOB_DATA(job_file.open())
        except Exception as e:
            raise InvalidTaskError(e)

        self.task_path = job_file

        last_year = self.at_data.last_year
        last_month = self.at_data.last_month
        last_day = self.at_data.last_day
        last_hour = self.at_data.last_hour
        last_minute = self.at_data.last_minute
        last_second = self.at_data.last_second
        last_millisecond = self.at_data.last_millisecond

        # Create a datetime object using the variables
        if last_year == 0 or last_month == 0 or last_day == 0:
            self.date = None
        else:
            timestamp = datetime.datetime(
                year=last_year,
                month=last_month,
                day=last_day,
                hour=last_hour,
                minute=last_minute,
                second=last_second,
                microsecond=last_millisecond * 1000,  # Convert millisecond to microsecond
            )
            # Convert the datetime object to ISO format timestamp string
            self.last_run_date = timestamp.isoformat()

        self.author = self.at_data.author.rstrip("\x00")
        self.version = self.at_data.file_version
        self.description = self.at_data.comment.rstrip("\x00")
        self.restart_on_failure_interval = self.minutes_duration_to_iso(self.at_data.retry_interval)
        self.restart_on_failure_count = self.at_data.retry_count
        self.dissalow_start_on_batteries = True if self.at_data.task_flags.disallow_battery else False
        self.stop_going_on_batteries = True if self.at_data.task_flags.stop_battery else False
        self.run_only_network_available = True if self.at_data.task_flags.internet_connected else False
        self.wake_to_run = True if self.at_data.task_flags.wake_to_run else False
        self.enabled = False if self.at_data.task_flags.disabled else True
        self.hidden = True if self.at_data.task_flags.hidden else False
        self.idle_duration = self.minutes_duration_to_iso(self.at_data.idle_wait)
        self.idle_wait_timeout = self.minutes_duration_to_iso(self.at_data.idle_deadline)
        self.idle_stop_on_idle_end = True if self.at_data.task_flags.stop_on_idle_end else False
        self.idle_restart_on_idle = True if self.at_data.task_flags.restart_on_idle else False
        self.execution_time_limit = round(self.at_data.max_run_time / 60000)
        self.execution_time_limit = self.minutes_duration_to_iso(self.execution_time_limit)
        self.run_only_idle = True if self.at_data.task_flags.only_idle else False
        self.data = self.at_data.user_data

        # check which prio bit is set
        for key, value in self.at_data.task_prio._values.items():
            if value:
                self.priority = key

    def get_actions(self) -> Iterator[TargetRecordDescriptor]:
        """Get the at job task actions.

        Yields:
            An iterator of at job task actions.
        """
        action_type = "Exec"
        command = self.at_data.app_name.rstrip("\x00")
        args = self.at_data.parameters.rstrip("\x00")
        wrkdir = self.at_data.working_dir.rstrip("\x00")

        yield ExecRecord(
            action_type=action_type,
            command=command,
            arguments=args,
            working_directory=wrkdir,
        )

    def get_triggers(self) -> Iterator[GroupedRecord]:
        """Get the job task triggers.

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

            repetition_interval = self.minutes_duration_to_iso(trigger.minutes_interval)
            repetition_duration = self.minutes_duration_to_iso(trigger.minutes_duration)
            repetition_stop_duration_end = True if trigger.trigger_flags.kill_at_end == 1 else False
            execution_time_limit = self.minutes_duration_to_iso(round(self.at_data.max_run_time / 60000))

            base = TriggerRecord(
                enabled=enabled,
                start_boundary=start_boundary,
                end_boundary=end_boundary,
                repetition_interval=repetition_interval,
                repetition_duration=repetition_duration,
                repetition_stop_duration_end=repetition_stop_duration_end,
                execution_time_limit=execution_time_limit,
            )
            padding_record = PaddingTriggerRecord(
                padding=trigger.padding,
                reserved2=trigger.reserved2,
                reserved3=trigger.reserved3,
            )

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
                )

                yield GroupedRecord("filesystem/windows/task/daily", [base, record, padding_record])

            if trigger_type == "WEEKLY":
                interval = trigger.trigger_specific0

                # Find weekdays corresponding with trigger specific flags
                days_of_week = self.get_days_of_week(trigger.trigger_specific1)
                unused = [trigger.trigger_specific2]

                record = WeeklyTriggerRecord(
                    weeks_between_triggers=interval,
                    days_of_week=days_of_week,
                    unused=unused,
                )

                yield GroupedRecord("filesystem/windows/task/weekly", [base, record, padding_record])

            if trigger_type == "MONTHLYDATE":
                # Convert trigger_specific fields to binary, remove the "0b" prefix, and pad with zeroes to 16 digits
                day_flag_part1 = bin(trigger.trigger_specific0)[2:].zfill(16)
                day_flag_part2 = bin(trigger.trigger_specific1)[2:].zfill(16)
                # Concatenate the two binary strings to form the complete day_flag
                day_of_month_flag = day_flag_part2 + day_flag_part1
                # Reverse the day_flag string (LE), find the index of "1", add 1 to get the day of the month
                day_of_month = day_of_month_flag[::-1].index("1") + 1

                # Find months corresponding with trigger specific flags
                months_of_year = self.get_months_of_year(trigger.trigger_specific2)

                record = MonthlyDateTriggerRecord(
                    day_of_month=day_of_month,
                    months_of_year=months_of_year,
                )

                yield GroupedRecord("filesystem/windows/task/monthly_date", [base, record, padding_record])

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
                days = self.get_days_of_week(trigger.trigger_specific1)
                months = self.get_months_of_year(trigger.trigger_specific2)
                record = MonthlyDowTriggerRecord(
                    which_week=week,
                    days_of_week=days,
                    months_of_year=months,
                )

                yield GroupedRecord("filesystem/windows/task/monthly_dow", [base, record, padding_record])

    def minutes_duration_to_iso(self, minutes: int) -> Optional[str]:
        """Convert the given number of minutes to an ISO 8601 duration format string, like those found in the xml tasks.
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

    def get_flags_data(self, flags: int, items: list[str]) -> Iterator[str]:
        """Create a generator of items corresponding to the flags.

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

    def get_months_of_year(self, flags: int) -> list[str]:
        """Convert 16-bit flags to a list of months of the year.

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
        return list(self.get_flags_data(flags, months))

    def get_days_of_week(self, flags: int) -> list[str]:
        """Get the list of weekdays corresponding to the given trigger specific 16-bit flags.

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
        return list(self.get_flags_data(flags, weekdays))
