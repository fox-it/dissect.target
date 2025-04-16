from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows.generic import UserRegistryRecordDescriptor

if TYPE_CHECKING:
    from collections.abc import Iterator

WinRarRecord = UserRegistryRecordDescriptor(
    "application/productivity/winrar",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)


class WinRarPlugin(Plugin):
    """Windows WinRAR GUI plugin."""

    BASE_KEY = "HKEY_CURRENT_USER\\Software\\WinRAR"

    def check_compatible(self) -> None:
        if not self.target.has_function("registry") or not list(self.target.registry.keys(self.BASE_KEY)):
            raise UnsupportedPluginError("No WinRAR registry keys found on target")

    @export(record=WinRarRecord)
    def winrar(self) -> Iterator[WinRarRecord]:
        """Return all available WinRAR history registry key values."""
        keys = [
            "ArcHistory",
            "DialogEditHistory\\ArcName",
            "DialogEditHistory\\ExtrPath",
        ]

        for key in keys:
            for r in self.target.registry.keys(f"{self.BASE_KEY}\\{key}"):
                user = self.target.registry.get_user(r)
                for v in r.values():
                    yield WinRarRecord(
                        ts=r.ts,
                        path=self.target.fs.path(v.value),
                        _key=r,
                        _user=user,
                        _target=self.target,
                    )
