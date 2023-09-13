from typing import Iterator

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

CmdlineRecord = TargetRecordDescriptor(
    "linux/proc/cmdline",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("varint", "pid"),
        ("string", "state"),
        ("string", "cmdline"),
    ],
)


class CmdlinePlugin(Plugin):
    def check_compatible(self) -> None:
        self.target.proc

    @export(record=CmdlineRecord)
    def cmdline(self) -> Iterator[CmdlineRecord]:
        """Return the complete command line for all processes.

        If, after an execve(2), the process modifies its argv strings, those changes will show up here. This is not the
        same thing as modifying the argv array.

        Think of this output as the command line that the process wants you to see.

        Yields CmdlineRecord with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The starttime of the process.
            name (string): The name of the process.
            pid (int): The process ID of the process.
            cmdline (string): The complete commandline of the process.
        """

        for process in self.target.proc.processes():
            yield CmdlineRecord(
                ts=process.starttime,
                name=process.name,
                pid=process.pid,
                state=process.state,
                cmdline=process.cmdline,
                _target=self.target,
            )
