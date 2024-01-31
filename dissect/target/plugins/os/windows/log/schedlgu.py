from __future__ import annotations

import logging
import re
import warnings
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

warnings.simplefilter(action="ignore", category=FutureWarning)
log = logging.getLogger(__name__)

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

JOB_REGEX_PATTERN = re.compile(r"\"(.*?)\" \((.*?)\)")
SCHEDLGU_REGEX_PATTERN = re.compile(r"\".+\n.+\n\s{4}.+\n|\".+\n.+", re.MULTILINE)


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
        try:
            ts = datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p")
        except ValueError:
            ts = datetime.strptime(ts, "%d-%m-%Y %H:%M:%S")

        return ts

    @staticmethod
    def _parse_job(line: str) -> tuple[str, Optional[str]]:
        matches = JOB_REGEX_PATTERN.match(line)
        if matches:
            return matches.groups()

        log.warning("SchedLgU failed to parse job and command from line: '%s'. Returning line.", line)
        return line, None

    @classmethod
    def from_line(cls, line: str) -> SchedLgU:
        """Parse a group of SchedLgU.txt lines."""
        event = cls()
        lines = line.splitlines()

        # Events can have 2 or 3 lines as a group in total. An example of a complete task job event is:
        # "Symantec NetDetect.job" (NDETECT.EXE)
        #     Finished 14-9-2003 13:21:01
        #     Result: The task completed with an exit code of (65).
        if len(lines) == 3:
            event.job, event.command = cls._parse_job(lines[0])
            event.status, event.ts = lines[1].split(maxsplit=1)
            event.exit_code = int(lines[2].split("(")[1].rstrip(")."))

        # Events that have 2 lines as a group can be started task job event or the Task Scheduler Service. Examples:
        #   "Symantec NetDetect.job" (NDETECT.EXE)
        #        Started at 14-9-2003 13:26:00
        elif len(lines) == 2 and ".job" in lines[0]:
            event.job, event.command = cls._parse_job(lines[0])
            event.status, event.ts = lines[1].split(maxsplit=1)

        # Events without a task job event are the Task Scheduler Service events. Which can look like this:
        # "Task Scheduler Service"
        #      Exited at 14-9-2003 13:40:24
        # OR
        # "Task Scheduler Service"
        # 6.0.6000.16386 (vista_rtm.061101-2205)
        elif len(lines) == 2:
            event.job = lines[0].strip('"')

            if lines[1].startswith("\t") or lines[1].startswith(" "):
                event.status, event.ts = lines[1].split(maxsplit=1)
            else:
                event.version = lines[1]

        if event.ts:
            event.ts = cls._sanitize_ts(event.ts)

        return event


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
        """Return all events in the Task Scheduler Service transaction log file (SchedLgU.txt).

        Older Windows systems may log ``.job`` tasks that get started remotely in the SchedLgU.txt file.
        In addition, this log file records when the Task Scheduler service starts and stops.

        Adversaries may use malicious ``.job`` files to gain persistence on a system.

        Yield:
            ts (datetime): The timestamp of the event.
            job (str): The name of the ``.job`` file.
            command (str): The command executed.
            status (str): The status of the event (finished, completed, exited, stopped).
            exit_code (int): The exit code of the event.
            version (str): The version of the Task Scheduler service.
        """

        for path in self.paths:
            content = path.read_text(encoding="UTF-16", errors="surrogateescape")

            for match in re.findall(SCHEDLGU_REGEX_PATTERN, content):
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
