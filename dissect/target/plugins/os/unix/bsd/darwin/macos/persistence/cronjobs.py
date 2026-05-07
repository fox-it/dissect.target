from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target


CronjobRecord = TargetRecordDescriptor(
    "macos/cronjob",
    [
        ("string", "minute"),
        ("string", "hour"),
        ("string", "day"),
        ("string", "month"),
        ("string", "weekday"),
        ("string", "command"),
        ("path", "source"),
    ],
)

EnvironmentVariableRecord = TargetRecordDescriptor(
    "macos/environmentvariable",
    [
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
    ],
)

RE_CRONJOB = re.compile(
    r"""
        ^
        (?P<minute>\S+)
        \s+
        (?P<hour>\S+)
        \s+
        (?P<day>\S+)
        \s+
        (?P<month>\S+)
        \s+
        (?P<weekday>\S+)
        \s+
        (?P<command>.+)
        $
    """,
    re.VERBOSE,
)
RE_ENVVAR = re.compile(r"^(?P<key>[a-zA-Z_]+[a-zA-Z[0-9_])=(?P<value>.*)")


class CronjobPlugin(Plugin):
    """macOS cronjob plugin."""

    CRONTAB_DIRS = (
        "/usr/lib/cron/tabs",
        "/var/at/tabs",
        "/var/cron/tabs",
    )

    CRONTAB_FILES = ("/etc/crontab",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.crontabs = list(self.find_crontabs())

    def check_compatible(self) -> None:
        if not self.crontabs:
            raise UnsupportedPluginError("No crontab(s) found on target")

    def find_crontabs(self) -> Iterator[Path]:
        for crontab_dir in self.CRONTAB_DIRS:
            if not (dir := self.target.fs.path(crontab_dir)).exists():
                continue

            for file in dir.iterdir():
                if file.resolve().is_file():
                    yield file

        for crontab_file in self.CRONTAB_FILES:
            if (file := self.target.fs.path(crontab_file)).exists():
                yield file

    @export(record=[CronjobRecord, EnvironmentVariableRecord])
    def cronjobs(self) -> Iterator[CronjobRecord | EnvironmentVariableRecord]:
        """Yield cronjobs, and their configured environment variables on a macOS system.

        A cronjob is a scheduled task/command on a macOS system. Adversaries may use cronjobs to gain
        persistence on the system.
        """
        for file in self.crontabs:
            for line in file.open("rt"):
                line = line.strip()
                if line.startswith("#") or not line:
                    continue

                if match := RE_CRONJOB.search(line):
                    match = match.groupdict()

                    yield CronjobRecord(
                        **match,
                        source=file,
                        _target=self.target,
                    )

                # Some cron implementations allow for environment variables to be set inside crontab files.
                elif match := RE_ENVVAR.search(line):
                    match = match.groupdict()
                    yield EnvironmentVariableRecord(
                        **match,
                        source=file,
                        _target=self.target,
                    )

                else:
                    self.target.log.warning("Unable to match cronjob line in %s: '%s'", file, line)
