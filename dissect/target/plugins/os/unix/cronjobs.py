from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import (
    TargetRecordDescriptor,
    create_extended_descriptor,
)
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target

CronjobRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "unix/cronjob",
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
RE_ENVVAR = re.compile(r"^(?P<key>[a-zA-Z_]+[a-zA-Z[0-9_])=(?P<value>.*)")


class CronjobPlugin(Plugin):
    """Unix cronjob plugin."""

    CRONTAB_DIRS = (
        "/var/cron/tabs",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
        "/etc/cron.d",
        "/usr/local/etc/cron.d",  # FreeBSD
    )

    CRONTAB_FILES = (
        "/etc/crontab",
        "/etc/anacrontab",
    )

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
        """Yield cronjobs, and their configured environment variables on a Unix system

        A cronjob is a scheduled task/command on a Unix based system. Adversaries may use cronjobs to gain
        persistence on the system.

        Resources:
            - https://linux.die.net/man/8/cron
            - https://linux.die.net/man/1/crontab
            - https://linux.die.net/man/5/crontab
            - https://en.wikipedia.org/wiki/Cron
            - https://linux.die.net/man/8/anacron
            - https://manpages.ubuntu.com/manpages/oracular/en/man5/crontab.5.html
            - https://www.gnu.org/software/mcron/manual/mcron.html#Guile-Syntax
        """

        for file in self.crontabs:
            # Cronjobs in user crontab files do not have a user field specified.
            user = None
            if file.is_relative_to("/var/spool/cron/crontabs") or file.is_relative_to("/var/spool/cron/"):
                user = self.target.user_details.find(username=file.name)

            for line in file.open("rt"):
                line = line.strip()
                if line.startswith("#") or not line:
                    continue

                if match := RE_CRONJOB.search(line):
                    match = match.groupdict()

                    # We try to infer a possible user from the command. This can lead to false positives,
                    # due to differing implementations of cron across operating systems, which is why
                    # we choose not to change the 'command' from the cron line - unless the command
                    # starts with the found username plus a tab character. We try to weed out false
                    # positives by checking the inferred user with the target's users.
                    if not user:
                        try:
                            inferred_user, _ = re.split(r"\s", match["command"], maxsplit=1)
                            # If the inferred username exists on the target we assign that user to this cronjob.
                            if user := self.target.user_details.find(username=inferred_user.strip()):
                                pass

                            # If the inferred username is followed by a tab we remove the username from the command.
                            if match["command"].startswith(inferred_user + "\t"):
                                match["command"] = match["command"].replace(inferred_user + "\t", "", 1)
                        except ValueError:
                            pass

                    yield CronjobRecord(
                        **match,
                        source=file,
                        _user=user.user if user else None,
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
