from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


PrintJobRecord = TargetRecordDescriptor(
    "macos/printjobs/entry",
    [
        ("string", "filename"),
        ("string", "line"),
        ("path", "source"),
    ],
)


class MacOSPrintJobsPlugin(Plugin):
    """Plugin to parse macOS CUPS print job cache.

    The job.cache file in /private/var/spool/cups/cache/ contains
    a text-based record of print jobs processed by CUPS.
    """

    __namespace__ = "printjobs"

    CACHE_PATH = "private/var/spool/cups/cache/job.cache"

    def __init__(self, target):
        super().__init__(target)
        self._cache_path = self.target.fs.path("/").joinpath(self.CACHE_PATH)

    def check_compatible(self) -> None:
        if not self._cache_path.exists():
            raise UnsupportedPluginError("No CUPS job.cache found")

    @export(record=PrintJobRecord)
    def entries(self) -> Iterator[PrintJobRecord]:
        """Parse CUPS print job cache entries."""
        try:
            with self._cache_path.open("r") as fh:
                content = fh.read()

            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                yield PrintJobRecord(
                    filename=self._cache_path.name,
                    line=stripped,
                    source=self._cache_path,
                    _target=self.target,
                )
        except Exception as e:
            self.target.log.warning("Error parsing job.cache: %s", e)
