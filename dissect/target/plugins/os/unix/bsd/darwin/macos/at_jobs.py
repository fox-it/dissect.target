from __future__ import annotations

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
    """macOS at jobs plugin.

    The at utility schedules commands to be executed at a later time.

    References:
        - https://man.freebsd.org/cgi/man.cgi?query=at&sektion=1&format=html
        - github.com/freebsd/freebsd-src/blob/main/usr.bin/at/at.c
    """

    PATHS = ("/usr/lib/cron/jobs/*",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.at_jobs_files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.at_jobs_files):
            raise UnsupportedPluginError("No At Jobs files found")

    def _find_files(self) -> set:
        files = set()

        for pattern in self.PATHS:
            for path in self.target.fs.glob(pattern):
                files.add(self.target.fs.path(path))

        return files

    @export(record=AtJobsRecord)
    def at_jobs(self) -> Iterator[AtJobsRecord]:
        """Return macOS `at` job records.

        Yields AtJobsRecord with the following fields:

        .. code-block:: text

            queue (string): Queue identifier derived from the job filename.
            seq (varint): Sequence number derived from the job filename.
            execution_time (datetime): Execution time derived from the job filename.
            command (string): Command contents extracted from the job file.
            source (path): Path to the `at` job file.

        The job filename typically follows the structure:

            QSSSSSTTTTTTTT

        Where:
            Q = queue identifier
            S = sequence number (hexadecimal)
            T = execution time (hexadecimal, in minutes)

        Lines following the environment setup (typically after 'export OLDPWD') are treated
        as the command content.
        """
        for file in self.at_jobs_files:
            name = file.name

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
            with file.open("r") as f:
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
