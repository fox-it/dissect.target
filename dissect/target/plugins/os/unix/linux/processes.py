from typing import Iterator

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

ProcProcessRecord = TargetRecordDescriptor(
    "linux/proc/processes",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("string", "state"),
        ("varint", "pid"),
        ("datetime", "runtime"),
        ("varint", "ppid"),
        ("string", "parent"),
    ],
)


class ProcProcesses(Plugin):
    def check_compatible(self) -> None:
        self.target.proc

    @export(record=ProcProcessRecord)
    def processes(self) -> Iterator[ProcProcessRecord]:
        """Return the processes available in ``/proc`` and the stats associated with them.

        There is a numerical subdirectory for each running process; the subdirectory is named by the process ID.
        Each ``/proc/[pid]`` subdirectory contains various pseudo-files.

        Yields ProcProcessRecord with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The start time of the process.
            name (string): The name of the process.
            state (string): The state of the process.
            pid (int): The process ID of the process.
            runtime (datetime): The amount of time the process is running until moment of acquisition.
            ppid (int): The parent process ID of the process.
            parent (string): The name of the parent process ID.
        """

        for process in self.target.proc.processes():
            yield ProcProcessRecord(
                ts=process.starttime,
                name=process.name,
                pid=process.pid,
                runtime=process.runtime.seconds,
                ppid=process.ppid,
                state=process.state,
                parent=process.parent.name,
                _target=self.target,
            )
