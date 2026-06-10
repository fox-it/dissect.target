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

SafariDownloadsRecord = TargetRecordDescriptor(
    "macos/safari_downloads",
    [
        ("string[]", "download_history"),
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

    @export(record=SafariDownloadsRecord)
    def safari_downloads(self) -> Iterator[SafariDownloadsRecord]:
        """Return macOS Safari downloads.

        Yields SafariDownloadsRecords with the following fields:

        .. code-block:: text

            download_history (string[]): Download history.
            source (path): Path to the Downloads.plist file.
        """
        for file in self.files:
            plist = plistlib.load(file.open())

            yield SafariDownloadsRecord(
                download_history=plist.get("DownloadHistory"),
                source=file,
                _target=self.target,
            )


# Download history is empty in current test data
# TODO: Get test file with actual data
