from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


LocalTimeRecord = TargetRecordDescriptor(
    "macos/localtime/info",
    [
        ("string", "timezone"),
        ("path", "source"),
    ],
)


class MacOSLocalTimePlugin(Plugin):
    """Plugin to report the configured timezone on macOS.

    Locations:
        /etc/localtime (symlink)
        /private/var/db/timezone/localtime
    """

    __namespace__ = "localtime"

    PATHS = [
        "etc/localtime",
        "private/var/db/timezone/localtime",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._tz_paths = []
        for p in self.PATHS:
            path = self.target.fs.path("/").joinpath(p)
            if path.exists():
                self._tz_paths.append(path)

    def check_compatible(self) -> None:
        if not self._tz_paths:
            raise UnsupportedPluginError("No localtime files found")

    @export(record=LocalTimeRecord)
    def info(self) -> Iterator[LocalTimeRecord]:
        """Report the configured timezone from localtime symlink."""
        for tz_path in self._tz_paths:
            try:
                # Try to read the symlink target to extract timezone name
                timezone = ""
                try:
                    link_target = str(tz_path.readlink())
                    timezone = link_target.split("zoneinfo/", 1)[1] if "zoneinfo/" in link_target else link_target
                except OSError:
                    # Not a symlink; try to extract from the path string
                    path_str = str(tz_path)
                    timezone = path_str.split("zoneinfo/", 1)[1] if "zoneinfo/" in path_str else "unknown"

                yield LocalTimeRecord(
                    timezone=timezone,
                    source=tz_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error reading localtime %s: %s", tz_path, e)
