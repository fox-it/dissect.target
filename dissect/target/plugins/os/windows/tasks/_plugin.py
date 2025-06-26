from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record import GroupedRecord

from dissect.target.exceptions import InvalidTaskError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export
from dissect.target.plugins.os.windows.tasks.job import AtTask
from dissect.target.plugins.os.windows.tasks.records import (
    BaseTriggerRecord,
    BootTriggerRecord,
    CalendarTriggerRecord,
    ComHandlerRecord,
    DailyTriggerRecord,
    EventTriggerRecord,
    ExecRecord,
    IdleTriggerRecord,
    LogonTriggerRecord,
    MonthlyDateTriggerRecord,
    MonthlyDowTriggerRecord,
    RegistrationTrigger,
    SendEmailRecord,
    SessionStateChangeTriggerRecord,
    ShowMessageRecord,
    TimeTriggerRecord,
    WeeklyTriggerRecord,
    WnfTriggerRecord,
)
from dissect.target.plugins.os.windows.tasks.xml import ScheduledTasks

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

TaskRecord = TargetRecordDescriptor(
    "filesystem/windows/task",
    [
        ("path", "task_path"),
        ("string", "uri"),
        ("string", "security_descriptor"),
        ("string", "source"),
        ("datetime", "date"),
        ("datetime", "last_run_date"),
        ("string", "author"),
        ("string", "version"),
        ("string", "description"),
        ("string", "documentation"),
        ("string", "task_name"),
        ("string", "app_name"),
        ("string", "args"),
        ("string", "start_in"),
        ("string", "comment"),
        ("string", "run_as"),
        ("string", "cpassword"),
        ("boolean", "enabled"),
        ("string", "action"),
        ("string", "principal_id"),
        ("string", "user_id"),
        ("string", "logon_type"),
        ("string", "group_id"),
        ("string", "display_name"),
        ("string", "run_level"),
        ("string", "process_token_sid_type"),
        ("string", "required_privileges"),
        ("string", "restart_on_failure_interval"),
        ("string", "restart_on_failure_count"),
        ("string", "mutiple_instances_policy"),
        ("boolean", "disallow_start_on_batteries"),
        ("boolean", "stop_going_on_batteries"),
        ("boolean", "allow_start_on_demand"),
        ("boolean", "start_when_available"),
        ("string", "network_profile_name"),
        ("boolean", "run_only_network_available"),
        ("boolean", "wake_to_run"),
        ("boolean", "hidden"),
        ("string", "delete_expired_task_after"),
        ("string", "idle_duration"),
        ("string", "idle_wait_timeout"),
        ("boolean", "idle_stop_on_idle_end"),
        ("boolean", "idle_restart_on_idle"),
        ("string", "network_settings_name"),
        ("string", "network_settings_id"),
        ("string", "execution_time_limit"),
        ("string", "priority"),
        ("boolean", "run_only_idle"),
        ("boolean", "unified_scheduling_engine"),
        ("boolean", "disallow_start_on_remote_app_session"),
        ("string", "data"),
        ("string", "raw_data"),
    ],
)

TriggerRecord = TargetRecordDescriptor(
    "filesystem/windows/task/trigger",
    {
        ("string", "uri"),
        *BaseTriggerRecord.target_fields,
        *BootTriggerRecord.target_fields,
        *CalendarTriggerRecord.target_fields,
        *DailyTriggerRecord.target_fields,
        *EventTriggerRecord.target_fields,
        *IdleTriggerRecord.target_fields,
        *LogonTriggerRecord.target_fields,
        *MonthlyDateTriggerRecord.target_fields,
        *MonthlyDowTriggerRecord.target_fields,
        *RegistrationTrigger.target_fields,
        *SessionStateChangeTriggerRecord.target_fields,
        *TimeTriggerRecord.target_fields,
        *WeeklyTriggerRecord.target_fields,
        *WnfTriggerRecord.target_fields,
    },
)

ActionRecord = TargetRecordDescriptor(
    "filesystem/windows/task/action",
    {
        ("string", "uri"),
        *ComHandlerRecord.target_fields,
        *ExecRecord.target_fields,
        *SendEmailRecord.target_fields,
        *ShowMessageRecord.target_fields,
    },
)


class TasksPlugin(Plugin):
    """Plugin for retrieving scheduled tasks on a Windows system.

    Args:
        target: The target system.
    """

    PATHS = (
        "sysvol/windows/system32/tasks",
        "sysvol/windows/system32/tasks_migrated",
        "sysvol/windows/syswow64/tasks",
        "sysvol/windows/tasks",  # at.exe job file location
    )
    GLOB_PATHS = (
        "sysvol/windows/system32/GroupPolicy/DataStore/*/Machine/Preferences/ScheduledTasks/*",
        "sysvol/ProgramData/Microsoft/*/Preferences/ScheduledTasks/*",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.task_files = []

        for path in self.GLOB_PATHS:
            start_path, pattern = path.split("*", 1)
            for entry in self.target.fs.path(start_path).rglob("*" + pattern):
                if entry.is_file() and entry.suffix == ".xml":
                    self.task_files.append(entry)

        for file_path in self.PATHS:
            fpath = self.target.fs.path(file_path)
            if not fpath.exists():
                continue

            for entry in fpath.rglob("*"):
                if entry.is_file() and (entry.suffix.lower() == ".job" or not entry.suffix):
                    self.task_files.append(entry)

    def check_compatible(self) -> None:
        if len(self.task_files) == 0:
            raise UnsupportedPluginError("No task files")

    @export(record=[TaskRecord, TriggerRecord, ActionRecord])
    @arg(
        "--group",
        action="store_true",
        help="group each trigger and action record together with its corresponding parent task record",
    )
    def tasks(self, group: bool = False) -> Iterator[TaskRecord | TriggerRecord | ActionRecord | GroupedRecord]:
        """Return all scheduled tasks on a Windows system.

        On a Windows system, a scheduled task is a program or script that is executed on a specific time or at specific
        intervals. An adversary may leverage such scheduled tasks to gain persistence on a system.

        References:
            - https://en.wikipedia.org/wiki/Windows_Task_Scheduler

        Yields:
            The scheduled tasks found on the target.
        """
        target_tz = self.target.datetime.tzinfo

        for task_file in self.task_files:
            if not task_file.suffix or task_file.suffix == ".xml":
                try:
                    task_objects = ScheduledTasks(task_file).tasks
                except InvalidTaskError as e:
                    self.target.log.warning("Invalid task file encountered: %s", task_file)
                    self.target.log.debug("", exc_info=e)
                    continue
            else:
                task_objects = [AtTask(task_file, target_tz)]

            for task_object in task_objects:
                record_kwargs = {}
                for attr in TaskRecord.fields:
                    record_kwargs[attr] = getattr(task_object, attr, None)

                task_record = TaskRecord(**record_kwargs, _target=self.target)
                yield task_record

                # Actions
                for action in task_object.get_actions():
                    if group:
                        record = GroupedRecord("filesystem/windows/task/grouped", [task_record, action])
                    else:
                        record = ActionRecord(**action._asdict(), uri=task_record.uri, _target=self.target)
                    yield record

                # Triggers
                for trigger in task_object.get_triggers():
                    if group:
                        record = GroupedRecord("filesystem/windows/task/grouped", [task_record, trigger])
                    else:
                        record = TriggerRecord(**trigger._asdict(), uri=task_record.uri, _target=self.target)
                    yield record
