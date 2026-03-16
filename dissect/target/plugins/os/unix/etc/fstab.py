from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix._os import parse_fstab_entry

if TYPE_CHECKING:
    from collections.abc import Iterator

FstabEntryRecord = TargetRecordDescriptor(
    "linux/etc/fstab",
    [
        ("string", "device_path"),
        ("string", "mount_path"),
        ("string", "fs_type"),
        ("string[]", "options"),
        ("boolean", "is_dump"),
        ("varint", "pass_num"),
    ],
)


class FstabPlugin(Plugin):
    """Linux fstab file plugin."""

    __namespace__ = "etc"

    def check_compatible(self) -> None:
        if not self.target.fs.exists("/etc/fstab"):
            raise UnsupportedPluginError("No fstab file found on target")

    @export(record=FstabEntryRecord)
    def fstab(self) -> Iterator[FstabEntryRecord]:
        """Return the mount entries from ``/etc/fstab``.

        Yields FstabEntryRecord with the following fields:

        . code-block:: text

            device_path (string): The device path.
            mount_path (string): The mount path.
            fs_type (string): The filesystem type.
            options (string[]): The mount options.
            is_dump (boolean): The dump frequency flag.
            pass_num (varint): The pass number.
        """
        fstab_path = self.target.fs.path("/etc/fstab")
        with fstab_path.open("rt") as fstab_file:
            for line in fstab_file:
                try:
                    entry = parse_fstab_entry(line)
                except ValueError as e:
                    self.target.log.warning("Failed to parse fstab entry: %s", e)
                    continue

                fs_spec, mount_point, fs_type, options, is_dump, pass_num = entry
                yield FstabEntryRecord(
                    device_path=fs_spec,
                    mount_path=mount_point,
                    fs_type=fs_type,
                    options=options.split(","),
                    is_dump=is_dump,
                    pass_num=pass_num,
                    _target=self.target,
                )
