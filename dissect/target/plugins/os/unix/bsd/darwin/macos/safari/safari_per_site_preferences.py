from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import _build_userdirs
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_sqlite_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target


SQLiteSequenceRecord = TargetRecordDescriptor(
    "macos/safari_per_site_preferences/sqlite_sequence",
    [
        ("string", "table"),
        ("string", "name"),
        ("varint", "seq"),
        ("path", "source"),
    ],
)

PreferencesValuesRecord = TargetRecordDescriptor(
    "macos/safari_per_site_preferences/preferences_values",
    [
        ("string", "table"),
        ("varint", "id"),
        ("string", "preference_domain"),
        ("string", "preference"),
        ("varint", "preference_value"),
        ("datetime", "timestamp"),
        ("string", "sync_data"),
        ("string", "record_name"),
        ("path", "source"),
    ],
)


SafariPerSitePreferencesRecords = (
    SQLiteSequenceRecord,
    PreferencesValuesRecord,
)

FIELD_MAPPINGS = {
    "domain": "preference_domain",
}

CONVERT_TIMESTAMPS = {
    "timestamp": "2001",
}


class SafariPerSitePreferencesPlugin(Plugin):
    """macOS Safari per site preferences SQLite database plugin."""

    USER_PATH = ("Library/Safari/PerSitePreferences.db",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No PerSitePreferences.db files found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

    @export(record=SafariPerSitePreferencesRecords)
    def safari_per_site_preferences(
        self,
    ) -> Iterator[SafariPerSitePreferencesRecords]:
        """Return Safari per site preferences information.

        Yields the following record types:

        .. code-block:: text

            PreferencesValuesRecord:
                table (string): Name of the source table (preference_values).
                id (varint): Primary key of the row.
                preference_domain (string): Domain name the preference applies to.
                preference (string): Name of the preference.
                preference_value (varint): Value assigned to the preference.
                timestamp (datetime): Timestamp indicating when the preference was set or updated.
                sync_data (string): Synchronization metadata associated with the preference.
                record_name (string): Record name.
                source (path): Path to the PerSitePreferences.db database file.

            SQLiteSequenceTableRecord:
                table (string): Name of the source table (sqlite_sequence).
                name (string): Name of the table for which the sequence applies.
                seq (varint): Current autoincrement value for the table.
                source (path): Path to the PerSitePreferences.db database file.
        """
        yield from build_sqlite_records(
            self,
            self.files,
            SafariPerSitePreferencesRecords,
            field_mappings=FIELD_MAPPINGS,
            convert_timestamps=CONVERT_TIMESTAMPS,
        )

        # TODO: Add default_preferences table
