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


class WindowsApplicationsPlugin(Plugin):
    """Windows Applications plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.keys = list(self.target.registry.keys("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"))

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
        for uninstall in self.keys:
            for app in uninstall.subkeys():
                values = {value.name: value.value for value in app.values()}

                if install_date := values.get("InstallDate"):
                    install_date = datetime.datetime.strptime(install_date, "%Y%m%d").replace(
                        tzinfo=datetime.timezone.utc
                    )

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
