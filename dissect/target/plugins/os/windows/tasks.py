import warnings
from typing import Iterator

from flow.record import GroupedRecord

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows._tasks_job import AtTask
from dissect.target.plugins.os.windows._tasks_xml import XmlTask
from dissect.target.target import Target

warnings.simplefilter(action="ignore", category=FutureWarning)

TaskRecord = TargetRecordDescriptor(
    "filesystem/windows/task",
    [
        ("string", "uri"),
        ("string", "security_descriptor"),
        ("string", "source"),
        ("datetime", "date"),
        ("datetime", "last_run_date"),
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


class TasksPlugin(Plugin):
    """Plugin for retrieving scheduled tasks on a Windows system.

    Args:
        target: The target system.
    """

    ATTRIBUTES = [
        "uri",
        "security_descriptor",
        "source",
        "date",
        "last_run_date",
        "author",
        "version",
        "description",
        "documentation",
        "principal_id",
        "user_id",
        "logon_type",
        "display_name",
        "run_level",
        "process_token_sid_type",
        "required_privileges",
        "allow_start_on_demand",
        "restart_on_failure_interval",
        "restart_on_failure_count",
        "mutiple_instances_policy",
        "dissalow_start_on_batteries",
        "stop_going_on_batteries",
        "start_when_available",
        "network_profile_name",
        "run_only_network_available",
        "wake_to_run",
        "enabled",
        "hidden",
        "delete_expired_task_after",
        "idle_duration",
        "idle_wait_timeout",
        "idle_stop_on_idle_end",
        "idle_restart_on_idle",
        "network_settings_name",
        "network_settings_id",
        "execution_time_limit",
        "priority",
        "run_only_idle",
        "unified_scheduling_engine",
        "disallow_start_on_remote_app_session",
        "data",
        "_target",
    ]

    PATHS = [
        "sysvol/windows/system32/tasks",
        "sysvol/windows/system32/tasks_migrated",
        "sysvol/windows/syswow64/tasks",
        "sysvol/windows/tasks",  # at.exe job file location
    ]

    def __init__(self, target: Target):
        super().__init__(target)
        self.task_objects = []

        for file_path in self.PATHS:
            fpath = self.target.fs.path(file_path)
            if not fpath.exists():
                continue

            for entry in fpath.rglob("*"):
                if entry.is_file() and entry.suffix.lower() == ".job":
                    self.task_objects.append(AtTask(entry, target))
                elif entry.is_file() and not entry.suffix:
                    self.task_objects.append(XmlTask(entry, target))

    def check_compatible(self):
        if len(self.task_objects) == 0:
            raise UnsupportedPluginError("No task files")

    @export(record=DynamicDescriptor(["path", "datetime"]))
    def tasks(self) -> Iterator:
        """Return all scheduled tasks on a Windows system.

        On a Windows system, a scheduled task is a program or script that is executed on a specific time or at specific
        intervals. An adversary may leverage such scheduled tasks to gain persistence on a system.

        References:
            https://en.wikipedia.org/wiki/Windows_Task_Scheduler

        Yields:
            The scheduled tasks found on the target.
        """
        for task_object in self.task_objects:
            yield from self.get_task_fields(task_object)

    def get_task_fields(self, task_object) -> Iterator:
        """Get all the parsed task fields from a task.
        The generic fields are defined in ATTRIBUTES. XmlTasks and AtTasks have also unique fields defined.

        Args:
            task_object: The task object to extract fields from.

        Yields:
            The extracted task fields as TaskRecords and GroupedRecords.
        """
        record_kwargs = {}
        for attr in self.ATTRIBUTES:
            record_kwargs[attr] = getattr(task_object, attr, None)

        record = TaskRecord(**record_kwargs)
        yield record

        # Actions
        for action in task_object.get_actions():
            grouped = GroupedRecord("filesystem/windows/task/grouped", [record, action])
            yield grouped

        # Triggers
        for trigger in task_object.get_triggers():
            grouped = GroupedRecord("filesystem/windows/task/grouped", [record, trigger])
            yield grouped
