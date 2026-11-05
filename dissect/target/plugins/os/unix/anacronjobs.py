from __future__ import annotations

import datetime
import re
import shlex
from typing import TYPE_CHECKING

from dissect.util import ts

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import (
    TargetRecordDescriptor,
)
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.cronjobs import EnvironmentVariableRecord

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target

AnacronjobRecord = TargetRecordDescriptor(
    "unix/anacronjob",
    [
        ("string", "period_name"),
        ("varint", "delay_in_minutes"),
        ("string", "job_identify"),
        ("string", "command"),
        ("datetime", "ts_last_exec"),  # based on /var/spool/anacron/job_identify content and last modification time
        ("path", "source"),
    ],
)

RE_ANACRONJOB = re.compile(
    r"""
        ^
        (?P<period_name>\S+)
        \s+
        (?P<delay>\S+)
        \s+
        (?P<job_identify>\S+)
        \s+
        (?P<command>.+)
        $
    """,
    re.VERBOSE,
)


# From man :
# ``Spaces around VAR are removed. No spaces around VALUE are allowed (unless you want them to be part of the value).``

RE_ENVVAR = re.compile(r"^\s*(?P<key>[a-zA-Z_]+[a-zA-Z[0-9_])\s*=(?P<value>.*)")


class AnacronjobPlugin(Plugin):
    """Unix anacron plugin."""

    ANACRONTAB_FILES = (
        "/etc/anacrontab",  # Linux
        "/usr/local/etc/anacrontab",  # FreeBSD
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.anacrontabs = list(self.get_paths())

    def check_compatible(self) -> None:
        if not self.anacrontabs:
            raise UnsupportedPluginError("No anacrontab found on target")

    def _get_paths(self) -> Iterator[Path]:
        for anacrontab_file in self.ANACRONTAB_FILES:
            if (file := self.target.fs.path(anacrontab_file)).exists():
                yield file

    @export(record=[AnacronjobRecord, EnvironmentVariableRecord])
    def anacronjobs(self) -> Iterator[AnacronjobRecord | EnvironmentVariableRecord]:
        """Yield anacron jobs, and their configured environment variables on a Unix system.

        An anacron job is a scheduled task/command on a Unix based system. Adversaries may use anacronjobs to gain
        persistence on the system. This plugins also iterate over files executed using run-parts

        References:
            - https://linux.die.net/man/5/anacrontab
            - https://man.freebsd.org/cgi/man.cgi?anacron(8)
            - https://linux.die.net/man/8/anacron
        """
        for file in self.anacrontabs:
            for line in file.open("rt"):
                line = line.strip()
                ts_last_exec = None
                if line.startswith("#") or not line:
                    continue

                if match := RE_ANACRONJOB.search(line):
                    match = match.groupdict()
                    job_identify = match.get("job_identify", None)
                    command = match.get("command", None)
                    if (ts_file := self.target.fs.path(f"/var/spool/anacron/{job_identify}")).exists():
                        ts_file_stat = ts_file.stat()
                        ts_last_exec = ts.from_unix(ts_file_stat.st_mtime)
                        anacron_ts_value = ts_file.read_text(errors="backslashreplace").strip()
                        if ts_last_exec.strftime("%Y%m%d") != anacron_ts_value:
                            # incoherent value, maybe related to ts modification/data loss during collection
                            ts_last_exec = datetime.datetime.strptime(anacron_ts_value, "%Y%m%d")  # noqa: DTZ007
                    yield AnacronjobRecord(
                        period_name=match.get("period_name", None),
                        delay_in_minutes=match.get("delay", None),
                        job_identify=job_identify,
                        command=command,
                        ts_last_exec=ts_last_exec,
                        source=file,
                        _target=self.target,
                    )
                    if command:
                        splited = shlex.split(command)
                        # Anacron often use run-parts or nice run-parts to run a list of script in a directory
                        # Last part of the command is the name of the folder
                        if (
                            "run-parts" in splited[:2]
                            and (run_part_dir := self.target.fs.path(splited[-1])).exists()
                            and run_part_dir.is_dir()
                        ):
                            for f in run_part_dir.iterdir():
                                yield AnacronjobRecord(
                                    period_name=match.get("period_name", None),
                                    delay_in_minutes=match.get("delay", None),
                                    job_identify=job_identify,
                                    command=f,
                                    ts_last_exec=ts_last_exec,
                                    source=file,
                                    _target=self.target,
                                )

                # Anacron allows for Environment assignment
                elif match := RE_ENVVAR.search(line):
                    match = match.groupdict()
                    yield EnvironmentVariableRecord(
                        **match,
                        source=file,
                        _target=self.target,
                    )

                else:
                    self.target.log.warning("Unable to match anacronjob line in %s: '%s'", file, line)
