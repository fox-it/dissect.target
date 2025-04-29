from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers import configutil
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import (
    COMMON_APPLICATION_FIELDS,
    TargetRecordDescriptor,
)
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target

UnixApplicationRecord = TargetRecordDescriptor(
    "unix/application",
    COMMON_APPLICATION_FIELDS,
)


class UnixApplicationsPlugin(Plugin):
    """Unix Applications plugin."""

    SYSTEM_PATHS = (
        "/usr/share/applications/",
        "/usr/local/share/applications/",
        "/var/lib/snapd/desktop/applications/",
        "/var/lib/flatpak/exports/share/applications/",
    )

    USER_PATHS = (".local/share/applications/",)

    SYSTEM_APPS = ("org.gnome.",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.desktop_files = list(self._find_desktop_files())

    def _find_desktop_files(self) -> Iterator[TargetPath]:
        for dir in self.SYSTEM_PATHS:
            for file in self.target.fs.path(dir).glob("*.desktop"):
                yield file

        for user_details in self.target.user_details.all_with_home():
            for dir in self.USER_PATHS:
                for file in user_details.home_path.joinpath(dir).glob("*.desktop"):
                    yield file

    def check_compatible(self) -> None:
        if not self.desktop_files:
            raise UnsupportedPluginError("No application .desktop files found")

    @export(record=UnixApplicationRecord)
    def applications(self) -> Iterator[UnixApplicationRecord]:
        """Yield installed Unix GUI applications from GNOME and XFCE.

        Resources:
            - https://wiki.archlinux.org/title/Desktop_entries
            - https://specifications.freedesktop.org/desktop-entry-spec/latest/
            - https://unix.stackexchange.com/questions/582928/where-gnome-apps-are-installed

        Yields ``UnixApplicationRecord`` records with the following fields:

        .. code-block:: text

            ts_modified  (datetime): timestamp when the installation was modified
            ts_installed (datetime): timestamp when the application was installed on the system
            name         (string):   name of the application
            version      (string):   version of the application
            author       (string):   author of the application
            type         (string):   type of the application, either user or system
            path         (string):   path to the desktop file entry of the application
        """
        for file in self.desktop_files:
            config = configutil.parse(file, hint="ini").get("Desktop Entry") or {}
            stat = file.lstat()

            yield UnixApplicationRecord(
                ts_modified=stat.st_mtime,
                ts_installed=stat.st_btime if hasattr(stat, "st_btime") else None,
                name=config.get("Name"),
                version=config.get("Version"),
                path=config.get("Exec"),
                type="system" if config.get("Icon", "").startswith(self.SYSTEM_APPS) else "user",
                _target=self.target,
            )
