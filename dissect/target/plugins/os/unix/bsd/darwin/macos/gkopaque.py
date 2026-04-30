from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_sqlite_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

WhitelistRecord = TargetRecordDescriptor(
    "macos/gkopaque/whitelist",
    [
        ("string", "table"),
        ("string", "current"),
        ("string", "opaque"),
        ("path", "source"),
    ],
)

ConditionsRecord = TargetRecordDescriptor(
    "macos/gkopaque/conditions",
    [
        ("string", "table"),
        ("string", "label"),
        ("varint", "weight"),
        ("string", "conditions_source"),
        ("string", "identifier"),
        ("string", "version"),
        ("string", "conditions"),
        ("path", "source"),
    ],
)


GatekeeperOpaqueConfigurationRecords = (
    WhitelistRecord,
    ConditionsRecord,
)

FIELD_MAPPINGS = {
    "source": "conditions_source",
}


class GatekeeperOpaqueConfigurationPlugin(Plugin):
    """macOS gatekeeper opaque configuration plugin."""

    PATH = "/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = None
        self._resolve_file()

    def _resolve_file(self) -> None:
        path = self.target.fs.path(self.PATH)
        if path.exists():
            self.file = path

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No gkopaque.db file found")

    @export(record=GatekeeperOpaqueConfigurationRecords)
    def gkopaque(self) -> Iterator[GatekeeperOpaqueConfigurationRecords]:
        """Yield gatekeeper opaque configuration information."""
        yield from build_sqlite_records(
            self, (self.file,), GatekeeperOpaqueConfigurationRecords, field_mappings=FIELD_MAPPINGS
        )

        # Still missing merged table
