from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.sqlite3 import SQLite3

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import _build_userdirs

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
    """macOS identity services plugin.

    ids.db is a SQLite database used by macOS's Identity Services framework (IDS),
    the system that powers services like iMessage and FaceTime via the identityservicesd
    daemon to store local identity-related data and metadata.
    """

    USER_PATH = ("Library/IdentityServices/ids.db",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No ids.db files found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

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
        """Return identity services information.

        Yields SqliteDatabasePropertiesRecords with the following fields:

        .. code-block:: text

            table (string): Name of the source table (_SqliteDatabaseProperties).
            key (string): Key name.
            value (string): Value associated with the key.
            source (path): Path to the com.apple.airport.preferences.plist file.
        """
        for file in self.files:
            with SQLite3(file) as database:
                for row in database.table("_SqliteDatabaseProperties").rows():
                    yield SqliteDatabasePropertiesRecord(
                        table="_SqliteDatabaseProperties",
                        key=row.key,
                        value=row.value,
                        source=file,
                    )

            # TODO: Add outgoing_message, sqlite_sequence, incoming_message, outgoing_messages_to_delete tables
