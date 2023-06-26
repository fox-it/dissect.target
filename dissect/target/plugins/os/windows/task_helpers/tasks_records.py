from dissect.target.helpers.record import TargetRecordDescriptor

BootTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/boot_trigger",
    [
        ("string", "delay"),
    ],
)

CalendarTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/calendar_trigger",
    [
        ("string", "random_delay"),
        ("string", "schedule_by_day"),
        ("string", "schedule_by_week"),
        ("string", "schedule_by_month"),
        ("string", "schedule_by_day_of_week"),
    ],
)

DailyTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/daily",
    [
        ("uint16", "days_between_triggers"),
        ("uint16[]", "unused"),
    ],
)

ComHandlerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/action/comhandler",
    [
        ("string", "action_type"),
        ("string", "class_id"),
        ("string", "data"),
    ],
)

EventTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/event_trigger",
    [
        ("string", "subscription"),
        ("string", "delay"),
        ("string", "period_of_occurence"),
        ("string", "number_of_occurences"),
        ("string", "matching_elements"),
        ("string", "value_queries"),
    ],
)

ExecRecord = TargetRecordDescriptor(
    "filesystem/windows/task/action/exec",
    [
        ("string", "action_type"),
        ("string", "command"),
        ("string", "arguments"),
        ("string", "working_directory"),
    ],
)

IdleTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/idle_trigger",
    [],
)

LogonTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/logon_trigger",
    [
        ("string", "user_id"),
        ("string", "delay"),
    ],
)

TimeTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/time_trigger",
    [
        ("string", "random_delay"),
    ],
)

TriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger",
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

MonthlyDateTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/monthly_date",
    [
        ("string", "day_of_month"),
        ("string[]", "months_of_year"),
    ],
)

MonthlyDowTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/monthly_dow",
    [
        ("string", "which_week"),
        ("string[]", "days_of_week"),
        ("string[]", "months_of_year"),
    ],
)

PaddingTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/padding",
    [
        ("uint16", "padding"),
        ("uint16", "reserved2"),
        ("uint16", "reserved3"),
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
    ],
)

SessionStateChangeTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/session_state_change_trigger",
    [
        ("string", "user_id"),
        ("string", "delay"),
        ("string", "state_change"),
    ],
)

ShowMessageRecord = TargetRecordDescriptor(
    "filesystem/windows/task/action/show_message",
    [
        ("string", "tile"),
        ("string", "body"),
    ],
)

WeeklyTriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger/weekly",
    [
        ("uint16", "weeks_between_triggers"),
        ("string[]", "days_of_week"),
        ("uint16[]", "unused"),
    ],
)
