from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import _build_userdirs

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

SafariDownloadRecord = TargetRecordDescriptor(
    "macos/safari_downloads",
    [
        ("varint", "download_entry_progress_total_to_load"),
        ("varint", "download_entry_progress_bytes_so_far"),
        ("string", "download_entry_path"),
        ("datetime", "download_entry_date_added"),
        ("boolean", "download_entry_remove_when_done"),
        ("boolean", "download_entry_should_use_request_url_as_origin_url_if_necessary"),
        ("string", "download_entry_profile_uuid_string"),
        ("datetime", "download_entry_date_finished"),
        ("string", "download_entry_url"),
        ("string", "download_entry_sandbox_identifier"),
        ("bytes", "download_entry_bookmark_blob"),
        ("string", "download_entry_identifier"),
        ("path", "source"),
    ],
)


class SafariDownloadsPlugin(Plugin):
    """macOS Safari property list (plist) plugin.

    This plist file contains a record of downloaded files.
    This data is automatically deleted after one day by default.

    References:
        - https://medium.com/@cyberengage.org/p13-analyzing-safari-browser-apple-mail-data-and-recents-database-artifacts-on-macos-9b58848d70ec
    """

    USER_PATH = ("Library/Safari/Downloads.plist",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No Downloads.plist files found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

    @export(record=SafariDownloadRecord)
    def safari_downloads(self) -> Iterator[SafariDownloadRecord]:
        """Return macOS Safari downloads.

        Yields SafariDownloadRecords for each download with the following fields:

        .. code-block:: text

            download_entry_progress_total_to_load (varint): Total bytes size to download.
            download_entry_progress_bytes_so_far (varint): Amount of bytes downloaded so far.
            download_entry_path (string): Local file path of the download.
            download_entry_date_added (datetime): Timestamp when the download was added.
            download_entry_remove_when_done (boolean): Whether the download is removed after completion.
            download_entry_should_use_request_url_as_origin_url_if_necessary (boolean):
                Whether the request URL should be used as the origin URL if needed.
            download_entry_profile_uuid_string (string): Profile UUID associated with the download.
            download_entry_date_finished (datetime): Timestamp when the download completed.
            download_entry_url (string): Source URL of the download.
            download_entry_sandbox_identifier (string): Sandbox identifier for the download.
            download_entry_bookmark_blob (bytes): Bookmark data blob for the downloaded file.
            download_entry_identifier (string): Unique identifier of the download entry.
            source (path): Path to the Downloads.plist file.
        """
        for file in self.files:
            plist = plistlib.load(file.open())
            for download in plist.get("DownloadHistory"):
                yield SafariDownloadRecord(
                    download_entry_progress_total_to_load=download.get("DownloadEntryProgressTotalToLoad"),
                    download_entry_progress_bytes_so_far=download.get("DownloadEntryProgressBytesSoFar"),
                    download_entry_path=download.get("DownloadEntryPath"),
                    download_entry_date_added=download.get("DownloadEntryDateAddedKey"),
                    download_entry_remove_when_done=download.get("DownloadEntryRemoveWhenDoneKey"),
                    download_entry_should_use_request_url_as_origin_url_if_necessary=download.get(
                        "DownloadEntryShouldUseRequestURLAsOriginURLIfNecessaryKey"
                    ),
                    download_entry_profile_uuid_string=download.get("DownloadEntryProfileUUIDStringKey"),
                    download_entry_date_finished=download.get("DownloadEntryDateFinishedKey"),
                    download_entry_url=download.get("DownloadEntryURL"),
                    download_entry_sandbox_identifier=download.get("DownloadEntrySandboxIdentifier"),
                    download_entry_bookmark_blob=download.get("DownloadEntryBookmarkBlob"),
                    download_entry_identifier=download.get("DownloadEntryIdentifier"),
                    source=file,
                    _target=self.target,
                )
