from __future__ import annotations

import plistlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


OSVersionRecord = TargetRecordDescriptor(
    "macos/osinfo/version",
    [
        ("string", "product_name"),
        ("string", "product_version"),
        ("string", "build_version"),
        ("path", "source"),
    ],
)

InstallDateRecord = TargetRecordDescriptor(
    "macos/osinfo/install_date",
    [
        ("datetime", "ts_installed"),
        ("path", "source"),
    ],
)


class MacOSInfoPlugin(Plugin):
    """Plugin to parse macOS OS version and install date.

    Locations:
        /System/Library/CoreServices/SystemVersion.plist
        /private/var/db/.AppleSetupDone
    """

    __namespace__ = "osinfo"

    VERSION_PATHS = [
        "System/Library/CoreServices/SystemVersion.plist",
    ]

    SETUP_PATHS = [
        "private/var/db/.AppleSetupDone",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._version_paths = []
        self._setup_paths = []
        for p in self.VERSION_PATHS:
            path = self.target.fs.path("/").joinpath(p)
            if path.exists():
                self._version_paths.append(path)
        for p in self.SETUP_PATHS:
            path = self.target.fs.path("/").joinpath(p)
            if path.exists():
                self._setup_paths.append(path)

    def check_compatible(self) -> None:
        if not self._version_paths and not self._setup_paths:
            raise UnsupportedPluginError("No OS info files found")

    @export(record=OSVersionRecord)
    def version(self) -> Iterator[OSVersionRecord]:
        """Parse SystemVersion.plist for OS version information."""
        for ver_path in self._version_paths:
            try:
                with ver_path.open("rb") as fh:
                    data = plistlib.loads(fh.read())

                yield OSVersionRecord(
                    product_name=data.get("ProductName", ""),
                    product_version=data.get("ProductVersion", ""),
                    build_version=data.get("ProductBuildVersion", ""),
                    source=ver_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error parsing SystemVersion.plist %s: %s", ver_path, e)

    @export(record=InstallDateRecord)
    def install_date(self) -> Iterator[InstallDateRecord]:
        """Get install date from .AppleSetupDone file modification time."""
        for setup_path in self._setup_paths:
            try:
                mtime = setup_path.stat().st_mtime
                ts = datetime.fromtimestamp(mtime, tz=timezone.utc)

                yield InstallDateRecord(
                    ts_installed=ts,
                    source=setup_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error reading .AppleSetupDone %s: %s", setup_path, e)
