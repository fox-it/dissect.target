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

SafariUserNotificationPermissionsRecord = TargetRecordDescriptor(
    "macos/safari_user_notification_permissions",
    [
        ("varint", "permission"),
        ("datetime", "date_added"),
        ("string", "site"),
        ("path", "source"),
    ],
)


class SafariUserNotificationPermissionsPlugin(Plugin):
    """macOS Safari user notification permissions property list (plist) plugin.

    References:
        - https://www.magnetforensics.com/blog/macos-safari-preferences-and-privacy/
    """

    USER_PATH = ("Library/Safari/UserNotificationPermissions.plist",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No UserNotificationPermissions.plist files found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

    @export(record=SafariUserNotificationPermissionsRecord)
    def safari_user_notification_permissions(self) -> Iterator[SafariUserNotificationPermissionsRecord]:
        """Return macOS Safari user notification permissions.

        Yields SafariUserNotificationPermissionsRecords with the following fields:

        .. code-block:: text

            permission (varint): The notification permission value for the site.
            date_added (datetime): The timestamp when the permission entry was created.
            site (string): The website URL associated with the permission.
            source (path): Path to the UserNotificationPermissions.plist file.
        """
        for file in self.files:
            plist = plistlib.load(file.open())
            # The top-level keys in the plist represent website URLs (e.g., https://www.macworld.com)
            # for which Safari has stored notification permission entries.
            for key in plist:
                data = plist.get(key)
                yield SafariUserNotificationPermissionsRecord(
                    permission=data["Permission"],
                    date_added=data["Date Added"],
                    site=key,
                    source=file,
                    _target=self.target,
                )
