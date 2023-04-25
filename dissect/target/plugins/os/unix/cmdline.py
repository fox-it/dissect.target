from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

CmdlineRecordRecord = TargetRecordDescriptor(
    "unix/proc/cmdline",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("varint", "pid"),
        ("string", "state"),
        ("string", "cmdline"),
    ],
)


class EnvironPlugin(Plugin):
    def check_compatible(self) -> None:
        if not self.target.proc:
            raise UnsupportedPluginError("No /proc directory found")

    @export(record=CmdlineRecordRecord)
    def cmdline(self) -> Iterator[TargetRecordDescriptor]:
        """This plugin yields the complete command line for the process .

        If, after an execve(2), the process modifies its argv
        strings, those changes will show up here.  This is not the
        same thing as modifying the argv array.

        Think of this file as the command line that the process
        wants you to see.

        Yields CmdlineRecordRecord with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The starttime of the process.
            name (string): The name of the process.
            pid (int): The process ID of the process.
            cmdline (string): The complete commandline of the process.
        """

        for process in self.target.proc.processes():
            yield CmdlineRecordRecord(
                ts=process.starttime,
                name=process.name,
                pid=process.pid,
                state=process.state,
                cmdline=process.cmdline,
                _target=self.target,
            )
