from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

InstallationHistoryRecord = TargetRecordDescriptor(
    "macos/installation_history",
    [
        ("datetime", "ts"),
        ("string", "display_name"),
        ("string", "display_version"),
        ("string", "process_name"),
        ("path", "source"),
    ],
)


class InstallationHistoryPlugin(Plugin):
    """macOS Software installation history property list plugin.

    Extracts the history of installed applications and updates.

    References:
        - https://forensics.wiki/mac_os_x_10.9_artifacts_location/#software-installation
    """

    PATH = "/Library/Receipts/InstallHistory.plist"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = self.target.fs.path(self.PATH) if self.target.fs.path(self.PATH).exists() else None

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No InstallHistory.plist file found")

    @export(record=InstallationHistoryRecord)
    def installation_history(self) -> Iterator[InstallationHistoryRecord]:
        """Return installation history information.

        Yields InstallationHistoryRecord with the following fields:

        .. code-block:: text

            ts (datetime): Timestamp of the installation.
            display_name (string): Display name of the installed software.
            display_version (string): Display version of the installed software.
            process_name (string): Name of the installation process.
            source (path): Path to the InstallHistory.plist file.
        """
        plist = plistlib.load(self.file.open())
        data = plist[0]

        yield InstallationHistoryRecord(
            ts=data.get("date"),
            display_name=data.get("displayName"),
            display_version=data.get("displayVersion"),
            process_name=data.get("processName"),
            source=self.file,
            _target=self.target,
        )
