from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


FileDescriptorRecord = TargetRecordDescriptor(
    "linux/proc/fd",
    [
        ("datetime", "ts"),
        ("varint", "pid"),
        ("string", "name"),
        ("varint", "fd"),
        ("string", "path"),
        ("uint64", "pos"),
        ("string", "flags"),
    ],
)

class ProcFdPlugin(Plugin):
    """Linux process file descriptor plugin."""

    def check_compatible(self) -> None:
        if not self.target.has_function("proc"):
            raise UnsupportedPluginError("proc filesystem not available")

    @export(record=FileDescriptorRecord)
    def fd(self) -> Iterator[FileDescriptorRecord]:
        """Return information about open file descriptors for all processes.

        This plugin identifies files, sockets, pipes, and other artifacts
        currently in use by processes by parsing /proc/[pid]/fd and fdinfo.

        Yields FileDescriptorRecord with the following fields:

        .. code-block:: text

            ts (datetime): The modification timestamp of the fd directory.
            pid (varint): The process id (pid) of the process.
            name (string): The name associated to the pid.
            fd (varint): The file descriptor number.
            path (string): The resolved path or resource link.
            pos (uint64): The current file offset from fdinfo.
            flags (string): The access flags from fdinfo.
        """
        for process in self.target.proc.processes():
            for fd_obj in process.fds:
                try:
                    ts = fd_obj.path.stat().st_mtime
                except Exception:
                    ts = None
                yield FileDescriptorRecord(
                    ts=ts,
                    pid=process.pid,
                    name=process.name,
                    fd=fd_obj.number,
                    path=fd_obj.target,
                    pos=int(fd_obj.info.get("pos", 0)),
                    flags=fd_obj.info.get("flags", "0"),
                    _target=self.target,
                )
