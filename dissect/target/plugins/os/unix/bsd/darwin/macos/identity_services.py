from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.sqlite3 import SQLite3

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.general import _build_userdirs

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target


SqliteDatabasePropertiesRecord = TargetRecordDescriptor(
    "macos/identity_services",
    [
        ("string", "table"),
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
    ],
)


class IdentityServicesPlugin(Plugin):
    """macOS identity services plugin."""

    USER_PATH = ("Library/IdentityServices/ids.db",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.files = set()
        self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No ids.db files found")

    def _find_files(self) -> None:
        for _, path in _build_userdirs(self, self.USER_PATH):
            self.files.add(path)

    @export(
        record=[
            SqliteDatabasePropertiesRecord,
        ]
    )
    def identity_services(
        self,
    ) -> Iterator[
        [
            SqliteDatabasePropertiesRecord,
        ]
    ]:
        """Yield identity services information."""
        for file in self.files:
            with SQLite3(file) as database:
                for row in database.table("_SqliteDatabaseProperties").rows():
                    yield SqliteDatabasePropertiesRecord(
                        table="_SqliteDatabaseProperties",
                        key=row.key,
                        value=row.value,
                        source=file,
                    )

            # Still missing outgoing_message, sqlite_sequence, incoming_message, outgoing_messages_to_delete tables
