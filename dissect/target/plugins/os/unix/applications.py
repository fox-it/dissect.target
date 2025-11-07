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
    [*COMMON_APPLICATION_FIELDS, ("boolean", "autostart")],
)


class UnixApplicationsPlugin(Plugin):
    """Unix Applications plugin."""

    DESKTOP_SYSTEM_PATHS = (
        "/usr/share/applications/",
        "/usr/local/share/applications/",
        "/var/lib/snapd/desktop/applications/",
        "/var/lib/flatpak/exports/share/applications/",
    )
    DESKTOP_USER_PATHS = (".local/share/applications/",)

    AUTOSTART_SYSTEM_PATHS = ("/etc/xdg/autostart/",)
    AUTOSTART_USER_PATHS = (".config/autostart/",)

    SYSTEM_APPS = ("org.gnome.",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.desktop_files = list(self._find_desktop_files())
        self.autostart_desktop_files = list(self._find_autostart_desktop_files())

    def _find_desktop_files(self) -> Iterator[TargetPath]:
        yield from self._find_system_desktop_files(self.DESKTOP_SYSTEM_PATHS)
        yield from self._find_user_desktop_files(self.DESKTOP_USER_PATHS)

    def _find_autostart_desktop_files(self) -> Iterator[TargetPath]:
        yield from self._find_system_desktop_files(self.AUTOSTART_SYSTEM_PATHS)
        yield from self._find_user_desktop_files(self.AUTOSTART_USER_PATHS)

    def _find_system_desktop_files(self, paths: Iterator[str]) -> Iterator[TargetPath]:
        for dir in paths:
            yield from self.target.fs.path(dir).glob("*.desktop")

    def _find_user_desktop_files(self, paths: Iterator[str]) -> Iterator[TargetPath]:
        for user_details in self.target.user_details.all_with_home():
            for dir in paths:
                yield from user_details.home_path.joinpath(dir).glob("*.desktop")

    def check_compatible(self) -> None:
        if not (self.desktop_files or self.autostart_desktop_files):
            raise UnsupportedPluginError("No application .desktop files found")

    def _parse_desktop_entry(self, path: TargetPath, is_autostart: bool = False) -> dict:
        config = configutil.parse(path, hint="ini").get("Desktop Entry") or {}
        stat = path.lstat()

        return UnixApplicationRecord(
            ts_modified=stat.st_mtime,
            ts_installed=stat.st_btime if hasattr(stat, "st_btime") else None,
            name=config.get("Name"),
            version=config.get("Version"),
            path=config.get("Exec"),
            type=("system" if config.get("Icon", "").startswith(self.SYSTEM_APPS) else "user"),
            autostart=is_autostart,
            _target=self.target,
        )

    @export(record=UnixApplicationRecord)
    def applications(self) -> Iterator[UnixApplicationRecord]:
        """Yield installed Unix GUI applications from GNOME and XFCE.

        When desktop applications are placed inside certain directories (Autostart directories),
        these applications can be automatically started by the desktop environment.

        Resources:
            - https://wiki.archlinux.org/title/Desktop_entries
            - https://specifications.freedesktop.org/desktop-entry-spec/latest/
            - https://unix.stackexchange.com/questions/582928/where-gnome-apps-are-installed
            - https://www.freedesktop.org/wiki/Specifications/autostart-spec/
            - https://specifications.freedesktop.org/autostart-spec/latest/
            - https://www.welivesecurity.com/en/eset-research/unveiling-wolfsbane-gelsemiums-linux-counterpart-to-gelsevirine/


        Yields ``UnixApplicationRecord`` records with the following fields:

        .. code-block:: text

            ts_modified  (datetime): timestamp when the installation was modified
            ts_installed (datetime): timestamp when the application was installed on the system
            name         (string):   name of the application
            version      (string):   version of the application
            author       (string):   author of the application
            type         (string):   type of the application, either user or system
            path         (string):   path to the desktop file entry of the application
            autostart    (boolean):  True when the application is an autostart desktop application, else False
        """
        for file in self.desktop_files:
            yield self._parse_desktop_entry(file, is_autostart=False)
        for file in self.autostart_desktop_files:
            yield self._parse_desktop_entry(file, is_autostart=True)
