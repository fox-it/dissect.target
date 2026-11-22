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

PageURLRecord = TargetRecordDescriptor(
    "macos/safari_favicons/page_url",
    [
        ("string", "table"),
        ("string", "url"),
        ("string", "uuid"),
        ("path", "source"),
    ],
)

IconInfoRecord = TargetRecordDescriptor(
    "macos/safari_favicons/icon_info",
    [
        ("string", "table"),
        ("string", "uuid"),
        ("string", "url"),
        ("datetime", "timestamp"),
        ("varint", "width"),
        ("varint", "height"),
        ("boolean", "has_generated_representations"),
        ("path", "source"),
    ],
)

RejectedResourcesRecord = TargetRecordDescriptor(
    "macos/safari_favicons/rejected_resources",
    [
        ("string", "table"),
        ("string", "page_url"),
        ("string", "icon_url"),
        ("datetime", "timestamp"),
        ("path", "source"),
    ],
)


SafariFaviconRecords = (PageURLRecord, IconInfoRecord, RejectedResourcesRecord)

CONVERT_TIMESTAMPS = {
    "timestamp": "2001",
}


class SafariFaviconsPlugin(Plugin):
    """macOS Safari favicons SQLite database plugin."""

    USER_PATH = ("Library/Safari/Favicon Cache/favicons.db",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No favicons.db files found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

    @export(record=SafariFaviconRecords)
    def safari_favicons(
        self,
    ) -> Iterator[SafariFaviconRecords]:
        """Return Safari favicon information.

        Yields the following record types:

        .. code-block:: text

            PageURLRecord:
                table (string): Name of the source table (page_url).
                url (string): URL of the webpage.
                uuid (string): Unique identifier.
                source (path): Path to the favicons.db database file.

            IconInfoRecord:
                table (string): Name of the source table (icon_info).
                uuid (string): Unique identifier.
                url (string): URL of the favicon image.
                timestamp (datetime): Timestamp.
                width (varint): Width of the favicon.
                height (varint): Height of the favicon.
                has_generated_representations (boolean): Indicates whether the favicon has generated representations.
                source (path): Path to the favicons.db database file.

            RejectedResourcesRecord:
                table (string): Name of the source table (rejected_resources).
                page_url (string): URL of the webpage associated with the rejected favicon.
                icon_url (string): URL of the rejected favicon resource.
                timestamp (datetime): Timestamp.
                source (path): Path to the favicons.db database file.
        """
        yield from build_sqlite_records(self, self.files, SafariFaviconRecords, convert_timestamps=CONVERT_TIMESTAMPS)

        # TODO: Add database_info table
