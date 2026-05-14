from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_sqlite_records
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.general import _build_userdirs

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

AccessRecord = TargetRecordDescriptor(
    "macos/tcc/access",
    [
        ("string", "table"),
        ("string", "service"),
        ("string", "client"),
        ("varint", "client_type"),
        ("varint", "auth_value"),
        ("varint", "auth_reason"),
        ("varint", "auth_version"),
        ("string", "csreq"),
        ("string", "policy_id"),
        ("string", "indirect_object_identifier_type"),
        ("string", "indirect_object_identifier"),
        ("string", "indirect_object_code_identity"),
        ("varint", "flags"),
        ("datetime", "last_modified"),
        ("varint", "pid"),
        ("string", "pid_version"),
        ("string", "boot_uuid"),
        ("datetime", "last_reminded"),
        ("path", "source"),
    ],
)

KeyValueRecord = TargetRecordDescriptor(
    "macos/tcc/key_value",
    [
        ("string", "table"),
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
    ],
)

TCCRecords = (
    AccessRecord,
    KeyValueRecord,
)


class TCCPlugin(Plugin):
    """macOS transparency, consent, control (tcc) framework plugin."""

    SYSTEM_PATH = "/Library/Application Support/com.apple.TCC/TCC.db"
    USER_PATH = ("Library/Application Support/com.apple.TCC/TCC.db",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.files = set()
        self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No TCC.db files found")

    def _find_files(self) -> None:
        self.files.add(self.target.fs.path(self.SYSTEM_PATH))
        for _, path in _build_userdirs(self, self.USER_PATH):
            self.files.add(path)

    @export(record=TCCRecords)
    def tcc(
        self,
    ) -> Iterator[TCCRecords]:
        """Yield transparency, consent, control (tcc) framework information."""
        yield from build_sqlite_records(self, self.files, TCCRecords)

        # Still missing policies, active_policy, access_overrides, expired tables
