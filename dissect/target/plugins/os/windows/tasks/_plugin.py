from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record import GroupedRecord

from dissect.target.exceptions import InvalidTaskError, UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows.tasks.job import AtTask
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
        ("string", "enabled"),
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
        ("string", "raw_data"),
    ],
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

    @export(record=DynamicDescriptor(["path", "datetime"]))
    def tasks(self) -> Iterator[TaskRecord | GroupedRecord]:
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

                record = TaskRecord(**record_kwargs, _target=self.target)
                yield record

                # Actions
                for action in task_object.get_actions():
                    grouped = GroupedRecord("filesystem/windows/task/grouped", [record, action])
                    yield grouped

                # Triggers
                for trigger in task_object.get_triggers():
                    grouped = GroupedRecord("filesystem/windows/task/grouped", [record, trigger])
                    yield grouped
