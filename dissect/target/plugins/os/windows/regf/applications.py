from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import (
    COMMON_APPLICATION_FIELDS,
    TargetRecordDescriptor,
)
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

WindowsApplicationRecord = TargetRecordDescriptor(
    "windows/application",
    COMMON_APPLICATION_FIELDS,
)

KEYS = (
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
)


class WindowsApplicationsPlugin(Plugin):
    """Windows Applications plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        key_list = list(self.target.registry.keys(KEYS))
        """
        Removing all keys from Backup registry hives located in sysvol/windows/system32/config/RegBack
        Parsing keys from RegBack leads to duplicate applications. A VirtualHive might not have a filepath attribute.
        Checking if the attribute exists first. If not, it is assumed it's not from RegBack.
        """
        self.keys = [
            key for key in key_list if not hasattr(key.hive, "filepath") or "RegBack" not in key.hive.filepath.parts
        ]

    def check_compatible(self) -> None:
        if not self.target.has_function("registry"):
            raise UnsupportedPluginError("No Windows registry found")

        if not self.keys:
            raise UnsupportedPluginError("No 'Uninstall' registry keys found")

    @export(record=WindowsApplicationRecord)
    def applications(self) -> Iterator[WindowsApplicationRecord]:
        """Yields currently installed applications from the Windows registry.

        Use the Windows eventlog plugin (``evtx``, ``evt``) to parse install and uninstall events
        of applications and services (e.g. ``4697``, ``110707``, ``1034`` and ``11724``).

        Resources:
            - https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key

        Yields ``WindowsApplicationRecord`` records with the following fields:

        .. code-block:: text

            ts_modified  (datetime): timestamp when the installation was modified according to the registry
            ts_installed (datetime): timestamp when the application was installed according to the application
            name         (string):   name of the application
            version      (string):   version of the application
            author       (string):   author of the application
            type         (string):   type of the application, either user or system
            path         (string):   path to the installed location or installer of the application
        """

        def parse_datetime(date_string: str) -> datetime.datetime | None:
            """
            Parses a date string by trying a list of common formats.
            Returns a datetime object or None if all formats fail.
            """
            date_formats = [
                "%Y%m%d",  # e.g., 20231225
                "%m/%d/%Y",  # e.g., 12/25/2023
                "%d/%m/%Y",  # e.g., 25/12/2023
            ]
            for fmt in date_formats:
                try:
                    return datetime.datetime.strptime(date_string, fmt).replace(tzinfo=datetime.timezone.utc)
                except (ValueError, TypeError):  # noqa: PERF203
                    continue

            return None

        for uninstall in self.keys:
            for app in uninstall.subkeys():
                values = {value.name: value.value for value in app.values()}

                install_date = None
                if install_date_string := values.get("InstallDate"):
                    install_date = parse_datetime(str(install_date_string))

                yield WindowsApplicationRecord(
                    ts_modified=app.ts,
                    ts_installed=install_date,
                    name=values.get("DisplayName") or app.name,
                    version=values.get("DisplayVersion"),
                    author=values.get("Publisher"),
                    type="system" if values.get("SystemComponent") or not values else "user",
                    path=values.get("DisplayIcon") or values.get("InstallLocation") or values.get("InstallSource"),
                    _target=self.target,
                )
