from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

AtJobsRecord = TargetRecordDescriptor(
    "macos/at_jobs",
    [
        ("string", "queue"),
        ("varint", "seq"),
        ("datetime", "execution_time"),
        ("string", "command"),
        ("path", "source"),
    ],
)


class AtJobsPlugin(Plugin):
    """macOS at jobs plugin."""

    PATHS = ("/usr/lib/cron/jobs/*",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.at_jobs_files = set()
        self._find_files()

    def check_compatible(self) -> None:
        if not (self.at_jobs_files):
            raise UnsupportedPluginError("No At Jobs files found")

    def _find_files(self) -> None:
        for pattern in self.PATHS:
            for path in self.target.fs.glob(pattern):
                self.at_jobs_files.add(path)

    @export(record=AtJobsRecord)
    def at_jobs(self) -> Iterator[AtJobsRecord]:
        """Yield macOS `at` jobs.

        The filename of an `at` job follows this structure:

            QSSSSSTTTTTTTT

        Where:
            Q = queue identifier
            S = sequence number (hexadecimal)
            T = execution time (hexadecimal, in minutes)

        The execution time is derived from the hexadecimal value and converted to seconds.

        Within the job file, the line:

            OLDPWD=/usr/lib/cron; export OLDPWD

        typically marks the end of environment setup. Future lines are part of
        the command to be executed and are extracted as such.

        Yields:
            AtJobsRecord: Parsed `at` job record containing queue, sequence number,
            execution time and command.
        """
        for file in self.at_jobs_files:
            name = Path(file).name

            if name in (".SEQ", ".lockfile"):
                continue

            if len(name) < 6:
                continue

            queue = name[0]
            seq = int(name[1:6], 16)
            time_hex = name[6:]

            execution_time = None
            try:
                minutes = int(time_hex, 16)
                execution_time = minutes * 60
            except ValueError:
                pass

            command_line = False
            command = ""
            with self.target.fs.path(file).open("r") as f:
                for line in f:
                    if command_line:
                        command += line
                    else:
                        line = line.strip()

                        if not line or line.startswith(("#", "export")):
                            continue

                        line = line.split("#", 1)[0].strip()

                        if "export OLDPWD" in line:
                            command_line = True

            command = command.rstrip("\n")

            yield AtJobsRecord(
                queue=queue,
                seq=seq,
                execution_time=execution_time,
                command=command,
                source=file,
            )
