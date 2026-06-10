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

SafariPreferencesRecord = TargetRecordDescriptor(
    "macos/safari_preferences",
    [
        ("varint", "iio_launch_info"),
        ("path", "source"),
    ],
)


class SafariPreferencesPlugin(Plugin):
    """macOS Safari favicons SQLite database plugin.

    Parses Safari's configuration settings and a list of recent searches performed by the user.

    References:
        - https://medium.com/@cyberengage.org/p13-analyzing-safari-browser-apple-mail-data-and-recents-database-artifacts-on-macos-9b58848d70ec
    """

    USER_PATH = ("Library/Preferences/com.apple.Safari.plist",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No com.apple.Safari.plist files found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

    @export(record=SafariPreferencesRecord)
    def safari_preferences(self) -> Iterator[SafariPreferencesRecord]:
        """Return macOS Safari preferences.

        Yields SafariPreferencesRecords with the following fields:

        .. code-block:: text

            iio_launch_info (varint): Image I/O launch info.
            source (path): Path to the com.apple.Safari.plist file.
        """
        for file in self.files:
            plist = plistlib.load(file.open())

            yield SafariPreferencesRecord(
                iio_launch_info=plist.get("IIO_LaunchInfo"),
                source=file,
                _target=self.target,
            )

# I was only able to find a IIO_LaunchInfo field in the plist file on a fresh Tahoe system.
# TODO: Check if more fields show up in the plist file depending on user activity.
