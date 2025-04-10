from __future__ import annotations

import stat
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.filesystem.walkfs import FilesystemRecord

if TYPE_CHECKING:
    from collections.abc import Iterator

SuidRecord = TargetRecordDescriptor(
    "filesystem/unix/suid",
    FilesystemRecord.target_fields,
)


class SuidPlugin(Plugin):
    """Unix SUID binary plugin."""

    def check_compatible(self) -> None:
        if not self.target.has_function("walkfs") or self.target.os == "windows":
            raise UnsupportedPluginError("Unsupported plugin")

    @export(record=SuidRecord)
    def suid_binaries(self) -> Iterator[SuidRecord]:
        """Return all SUID binaries.

        A SUID binary allows all users to run it with the permissions of its owner. This means that a
        SUID binary owned by the root user can be run with root privileges by any user. Such binaries can be leveraged
        by an adversary to perform privilege escalation.

        References:
            - https://steflan-security.com/linux-privilege-escalation-suid-binaries/
        """
        for record in self.target.walkfs():
            if record.mode & stat.S_ISUID:
                yield SuidRecord(
                    **record._asdict(),
                    _target=self.target,
                )
