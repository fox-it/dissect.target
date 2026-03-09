from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.etc.fstab import FstabEntryRecord

if TYPE_CHECKING:
    from collections.abc import Iterator

MountRecord = TargetRecordDescriptor(
    "linux/proc/mounts",
    [("varint", "pid"), *FstabEntryRecord.target_fields],
)


class MountPlugin(Plugin):
    """Linux volatile proc environment plugin."""

    def check_compatible(self) -> None:
        if not self.target.has_function("proc"):
            raise UnsupportedPluginError("proc filesystem not available")

    @export(record=MountRecord)
    def mounts(self) -> Iterator[MountRecord]:
        """Return the mount points for all processes.

        Yields MountRecord with the following fields:

        . code-block:: text

            pid (varint): The process id (pid) of the process.
            device_path (string): The device path.
            mount_path (string): The mount path.
            fs_type (string): The filesystem type.
            options (string[]): The mount options.
            is_dump (boolean): The dump frequency flag.
            pass_num (varint): The pass number.
        """
        for process in self.target.proc.processes():
            for mount_entry in process.mounts():
                yield MountRecord(
                    pid=process.pid,
                    device_path=mount_entry.fs_spec,
                    mount_path=mount_entry.mount_path,
                    fs_type=mount_entry.fs_type,
                    options=mount_entry.options,
                    is_dump=mount_entry.is_dump,
                    pass_num=mount_entry.pass_num,
                    _target=self.target,
                )
