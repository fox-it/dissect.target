from __future__ import annotations

from dissect.target.helpers.record import TargetRecordDescriptor

BootTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/boot",
    [
        ("path", "source"),
    ],
)

CalendarTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/calendar",
    [
        ("path", "source"),
    ],
)

DailyTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/daily",
    [
        ("uint16", "days_between_triggers"),
        ("uint16[]", "unused"),
        ("path", "source"),
    ],
)

ComHandlerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/action/comhandler",
    [
        ("string", "action_type"),
        ("string", "class_id"),
        ("string", "com_data"),
        ("path", "source"),
    ],
)

EventTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/event",
    [
        ("string", "subscription"),
        ("string", "period_of_occurence"),
        ("uint16", "number_of_occurences"),
        ("string", "matching_elements"),
        ("string", "value_queries"),
        ("path", "source"),
    ],
)

ExecRecord = TargetRecordDescriptor(
    "filesystem/windows/task/action/exec",
    [
        ("string", "action_type"),
        ("string", "command"),
        ("string", "arguments"),
        ("string", "working_directory"),
        ("path", "source"),
    ],
)

IdleTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/idle",
    [
        ("path", "source"),
    ],
)

LogonTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/logon",
    [
        ("string", "user_id"),
        ("path", "source"),
    ],
)

TimeTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/time",
    [
        ("path", "source"),
    ],
)

BaseTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/base",
    [
        ("boolean", "trigger_enabled"),
        ("datetime", "start_boundary"),
        ("datetime", "end_boundary"),
        ("string", "repetition_interval"),
        ("string", "repetition_duration"),
        ("boolean", "repetition_stop_duration_end"),
        ("string", "execution_time_limit"),
        ("string", "delay"),
        ("string", "random_delay"),
        ("string", "trigger_data"),
        ("path", "source"),
    ],
)

MonthlyDateTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/monthly",
    [
        ("uint16[]", "day_of_month"),
        ("string[]", "months_of_year"),
        ("path", "source"),
    ],
)

MonthlyDowTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/monthly_dow",
    [
        ("uint16[]", "which_week"),
        ("string[]", "days_of_week"),
        ("string[]", "months_of_year"),
        ("path", "source"),
    ],
)

PaddingTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/padding",
    [
        ("uint16", "padding"),
        ("uint16", "reserved2"),
        ("uint16", "reserved3"),
        ("path", "source"),
    ],
)

SendEmailRecord = TargetRecordDescriptor(
    "filesystem/windows/task/action/send_email",
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
        ("path", "source"),
    ],
)

SessionStateChangeTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/session_state_change",
    [
        ("string", "user_id"),
        ("string", "state_change"),
        ("path", "source"),
    ],
)

ShowMessageRecord = TargetRecordDescriptor(
    "filesystem/windows/task/action/show_message",
    [
        ("string", "tile"),
        ("string", "body"),
        ("path", "source"),
    ],
)

WeeklyTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/weekly",
    [
        ("uint16", "weeks_between_triggers"),
        ("string[]", "days_of_week"),
        ("uint16[]", "unused"),
        ("path", "source"),
    ],
)

WnfTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/wnf",
    [
        ("string", "state_name"),
        ("path", "source"),
    ],
)

RegistrationTrigger = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/registration",
    [
        ("datetime", "date"),
        ("path", "source"),
    ],
)
