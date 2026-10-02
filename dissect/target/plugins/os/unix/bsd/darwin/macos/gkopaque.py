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
        ("bytes", "current"),
        ("bytes", "opaque"),
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
    """macOS gatekeeper opaque configuration plugin.

    Gatekeeper is a macOS security feature that checks the code signing of downloaded
    apps and blocks those that don't meet Apple's trust and policy requirements.
    /var/db/gkopaque.bundle/Contents/Resources/gkopaque.db contains a whitelist table of
    gatekeeper-trusted application code signature hashes and associated opaque values.
    It also includes a conditions table, which defines policy rules applied to
    specific applications.


    References:
        - https://indiestack.com/2014/10/gatekeepers-opaque-whitelist/
        - https://developer.apple.com/documentation/metal/mtlbinaryarchive/label?changes=_1&language=objc
    """

    PATH = "/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = self.target.fs.path(self.PATH) if self.target.fs.path(self.PATH).exists() else None

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No gkopaque.db file found")

    @export(record=GatekeeperOpaqueConfigurationRecords)
    def gkopaque(self) -> Iterator[GatekeeperOpaqueConfigurationRecords]:
        """Return macOS Gatekeeper opaque configuration database entries.

        Yields the following record types extracted from the
        gkopaque.db database:

        .. code-block:: text

            WhitelistRecord:
                table (string): Name of the source table (whitelist).
                current (bytes): Code Directory Hash (CDHash) identifying a trusted code object.
                opaque (bytes): Associated opaque validation data.
                source (path): Path to the gkopaque.db file.

            ConditionsRecord:
                table (string): Name of the source table (conditions).
                label (string): A string that identifies the library.
                weight (varint): Priority value assigned to the condition.
                conditions_source (string): Identifier indicating the origin of the condition rule.
                identifier (string): Bundle identifier associated with the condition rule.
                version (string): Version string for the condition.
                conditions (string): Condition expression used by Gatekeeper.
                source (path): Path to the gkopaque.db file.
        """
        yield from build_sqlite_records(
            self, (self.file,), GatekeeperOpaqueConfigurationRecords, field_mappings=FIELD_MAPPINGS
        )

        # TODO: Add merged table
