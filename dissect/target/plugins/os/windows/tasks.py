from __future__ import annotations

import re
import warnings
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Union

from dateutil import parser as dateutil
from flow.record import GroupedRecord

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows.task_helpers.tasks_job import AtTask
from dissect.target.plugins.os.windows.task_helpers.tasks_xml import ScheduledTasks

warnings.simplefilter(action="ignore", category=FutureWarning)

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

SchedLgURecord = TargetRecordDescriptor(
    "windows/tasks/log/schedlgu",
    [
        ("datetime", "ts"),
        ("string", "job"),
        ("string", "command"),
        ("string", "status"),
        ("uint32", "exit_code"),
        ("string", "version"),
    ],
)


@dataclass(order=True)
class SchedLgU:
    ts: datetime = None
    job: str = None
    status: str = None
    command: str = None
    exit_code: int = None
    version: str = None

    @staticmethod
    def _sanitize_ts(ts: str) -> datetime:
        # sometimes "at" exists before the timestamp
        ts = ts.strip("at ")
        return dateutil.parse(ts)

    @staticmethod
    def _parse_job(line: str) -> tuple[str, str]:
        job, command = line.split("(", maxsplit=1)
        command = command.rstrip(")")
        job = job.strip('"').rstrip('" ')

        return job, command

    @classmethod
    def from_line(cls, line: str) -> SchedLgU:
        """Parse a group of SchedLgU.txt lines."""
        event = cls()
        lines = line.splitlines()

        if len(lines) == 3:
            event.job, event.command = cls._parse_job(lines[0])
            event.status, event.ts = lines[1].split(maxsplit=1)
            event.exit_code = int(lines[2].split("(")[1].rstrip(")."))

        elif len(lines) == 2 and ".job" in lines[0]:
            event.job, event.command = cls._parse_job(lines[0])
            event.status, event.ts = lines[1].split(maxsplit=1)

        elif len(lines) == 2:
            event.job = lines[0].strip('"')

            if lines[1].startswith("\t") or lines[1].startswith("    "):
                event.status, event.ts = lines[1].split(maxsplit=1)
            else:
                event.version = lines[1]

        if event.ts:
            event.ts = cls._sanitize_ts(event.ts)

        return event


class TasksPlugin(Plugin):
    """Plugin for retrieving scheduled tasks on a Windows system.

    Args:
        target: The target system.
    """

    PATHS = {
        "sysvol/windows/system32/tasks",
        "sysvol/windows/system32/tasks_migrated",
        "sysvol/windows/syswow64/tasks",
        "sysvol/windows/tasks",  # at.exe job file location
    }
    GLOB_PATHS = [
        "sysvol/windows/system32/GroupPolicy/DataStore/*/Machine/Preferences/ScheduledTasks/*",
        "sysvol/ProgramData/Microsoft/*/Preferences/ScheduledTasks/*",
    ]

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
    def tasks(self) -> Iterator[Union[TaskRecord, GroupedRecord]]:
        """Return all scheduled tasks on a Windows system.

        On a Windows system, a scheduled task is a program or script that is executed on a specific time or at specific
        intervals. An adversary may leverage such scheduled tasks to gain persistence on a system.

        References:
            https://en.wikipedia.org/wiki/Windows_Task_Scheduler

        Yields:
            The scheduled tasks found on the target.
        """
        for task_file in self.task_files:
            if not task_file.suffix or task_file.suffix == ".xml":
                task_objects = ScheduledTasks(task_file).tasks
            else:
                task_objects = [AtTask(task_file, self.target)]

            for task_object in task_objects:
                record_kwargs = {}
                for attr in TaskRecord.fields.keys():
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


class SchedLgUPlugin(Plugin):
    """Plugin for parsing the Task Scheduler Service transaction log file (SchedLgU.txt)."""

    PATHS = {
        "sysvol/SchedLgU.txt",
        "sysvol/windows/SchedLgU.txt",
        "sysvol/windows/tasks/SchedLgU.txt",
        "sysvol/winnt/tasks/SchedLgU.txt",
    }

    def __init__(self, target: Target) -> None:
        self.target = target
        self.paths = [self.target.fs.path(path) for path in self.PATHS if self.target.fs.path(path).exists()]

    def check_compatible(self) -> None:
        if len(self.paths) == 0:
            raise UnsupportedPluginError("No SchedLgU.txt file found.")

    @export(record=SchedLgURecord)
    def schedlgu(self) -> Iterator[SchedLgURecord]:
        """Return all evnets in the Task Scheduler Service transaction log file (SchedLgU.txt).

        Older Windows systems may log ``.job`` tasks that get started remotely in the SchedLgU.txt file.
        In addition this log file records when the Task Scheduler service starts and stops.

        Adversaries may use malious ``.job`` files to gain persistence on a system.

        Yield:
            ts (datetime): The timestamp of the event.
            job (str): The name of the ``.job`` file.
            command (str): The command executed.
            status (str): The status of the event (Finished, completed, exited, stopped).
            exit_code (int): The exit code of the event.
            version (str): The version of the Task Scheduler service.
        """

        for path in self.paths:
            content = path.read_text(encoding="UTF-16", errors="surrogateescape")
            pattern = re.compile(r"\".+\n.+\n\s{4}.+\n|\".+\n.+", re.MULTILINE)

            for match in re.findall(pattern, content):
                event = SchedLgU.from_line(match)

                yield SchedLgURecord(
                    ts=event.ts,
                    job=event.job,
                    command=event.command,
                    status=event.status,
                    exit_code=event.exit_code,
                    version=event.version,
                    _target=self.target,
                )
