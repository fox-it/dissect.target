from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import WindowsApplicationRecord
from dissect.target.plugin import Plugin, export
from dissect.target.target import Target


class WindowsApplicationsPlugin(Plugin):
    """Windows Applications plugin."""

    KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"

    def __init__(self, target: Target):
        super().__init__(target)
        self.keys = list(self.target.registry.keys(self.KEY))

    def check_compatible(self) -> None:
        if not self.target.has_function("registry"):
            raise UnsupportedPluginError("No Windows registry found")

        if not self.keys:
            raise UnsupportedPluginError("No 'Uninstall' registry keys found")

    @export(record=WindowsApplicationRecord)
    def applications(self) -> Iterator[WindowsApplicationRecord]:
        """Yields installed applications from the Windows registry."""
        for uninstall in self.keys:
            for app in uninstall.subkeys():
                values = {value.name: value.value for value in app.values()}

                yield WindowsApplicationRecord(
                    ts_modified=app.ts,
                    ts_installed=values.get("InstallDate"),
                    name=values.get("DisplayName"),
                    version=values.get("DisplayVersion"),
                    author=values.get("Publisher"),
                    type="system" if values.get("SystemComponent") else "user",
                    path=values.get("DisplayIcon") or values.get("InstallLocation") or values.get("InstallSource"),
                    _target=self.target,
                )
