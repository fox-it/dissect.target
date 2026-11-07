from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


ApplicationRecord = TargetRecordDescriptor(
    "macos/applications/installed",
    [
        ("string", "app_name"),
        ("string", "display_name"),
        ("string", "bundle_identifier"),
        ("string", "bundle_version"),
        ("string", "short_version"),
        ("string", "executable"),
        ("string", "min_system_version"),
        ("string", "sdk_name"),
        ("string", "compiler"),
        ("string", "copyright"),
        ("string", "category"),
        ("string", "app_location"),
        ("path", "source"),
    ],
)


class MacOSApplicationsPlugin(Plugin):
    """Plugin to parse installed macOS applications from Info.plist.

    Parses application metadata from:
    - /Applications/*/Contents/Info.plist (system-wide)
    - ~/Applications/*/Contents/Info.plist (per-user)
    """

    __namespace__ = "applications"

    APP_GLOBS = [
        "Applications/*/Contents/Info.plist",
        "Users/*/Applications/*/Contents/Info.plist",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._plist_paths = []
        for pattern in self.APP_GLOBS:
            self._plist_paths.extend(self.target.fs.path("/").glob(pattern))
        self._plist_paths.sort()

    def check_compatible(self) -> None:
        if not self._plist_paths:
            raise UnsupportedPluginError("No application Info.plist files found")

    def _read_plist(self, path):
        try:
            with path.open("rb") as fh:
                return plistlib.loads(fh.read())
        except Exception:
            return None

    @export(record=ApplicationRecord)
    def installed(self) -> Iterator[ApplicationRecord]:
        """Parse installed applications from Info.plist files."""
        for plist_path in self._plist_paths:
            try:
                data = self._read_plist(plist_path)
                if data is None:
                    continue

                # Derive app location from path: .../SomeApp.app/Contents/Info.plist
                app_dir = str(plist_path.parent.parent)

                yield ApplicationRecord(
                    app_name=data.get("CFBundleName", ""),
                    display_name=data.get("CFBundleDisplayName", data.get("CFBundleName", "")),
                    bundle_identifier=data.get("CFBundleIdentifier", ""),
                    bundle_version=data.get("CFBundleVersion", ""),
                    short_version=data.get("CFBundleShortVersionString", ""),
                    executable=data.get("CFBundleExecutable", ""),
                    min_system_version=data.get("LSMinimumSystemVersion", ""),
                    sdk_name=data.get("DTSDKName", ""),
                    compiler=data.get("DTCompiler", ""),
                    copyright=data.get("NSHumanReadableCopyright", ""),
                    category=data.get("LSApplicationCategoryType", ""),
                    app_location=app_dir,
                    source=plist_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error parsing %s: %s", plist_path, e)
