from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, get_args

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

CronjobRecord = TargetRecordDescriptor(
    "unix/cronjob",
    [
        ("string", "minute"),
        ("string", "hour"),
        ("string", "day"),
        ("string", "month"),
        ("string", "weekday"),
        ("string", "user"),
        ("string", "command"),
        ("path", "source"),
    ],
)

EnvironmentVariableRecord = TargetRecordDescriptor(
    "unix/environmentvariable",
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
RE_ENVVAR = re.compile(
    r"""
        ^
        ([a-zA-Z_]+[a-zA-Z[0-9_])=(.*)
    """,
    re.VERBOSE,
)


class CronjobPlugin(Plugin):
    """Unix cronjob plugin."""

    CRONTAB_DIRS = [
        "/var/cron/tabs",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
        "/etc/cron.d",
        "/usr/local/etc/cron.d",  # FreeBSD
    ]

    CRONTAB_FILES = [
        "/etc/crontab",
        "/etc/anacrontab",
    ]

    def __init__(self, target):
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
        """Yield cronjobs on a unix system.

        A cronjob is a scheduled task/command on a Unix based system. Adversaries may use cronjobs to gain
        persistence on the system.

        Resources:
            - https://linux.die.net/man/8/cron
            - https://linux.die.net/man/1/crontab
            - https://linux.die.net/man/5/crontab
            - https://en.wikipedia.org/wiki/Cron
        """

        for file in self.crontabs:
            for line in file.open("rt"):
                line = line.strip()
                if line.startswith("#") or not len(line):
                    continue

                if match := RE_CRONJOB.search(line):
                    match = match.groupdict()

                    # Cronjobs in user crontab files do not have a user field specified.
                    user = None
                    if file.is_relative_to("/var/spool/cron/crontabs"):
                        user = file.name
                    else:
                        user, match["command"] = re.split(r"\s", match["command"], maxsplit=1)

                    match["command"] = match["command"].strip()

                    yield CronjobRecord(
                        **match,
                        user=user,
                        source=file,
                        _target=self.target,
                    )

                elif match := RE_ENVVAR.search(line):
                    yield EnvironmentVariableRecord(
                        key=match.group(1),
                        value=match.group(2),
                        source=file,
                        _target=self.target,
                    )

                else:
                    self.target.log.warning("Unable to match cronjob line in %s: '%s'", file, line)
