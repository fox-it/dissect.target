from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.cstruct import cstruct

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

recent_files_def = """
    struct header {
        uint32  magic;
        uint32  unk0;
        uint32  unk1;
        uint32  unk2;
        uint32  checksum;
    };

    struct entry {
        uint32  length;
        wchar   path[length + 1];
    };
    """
c_recent_files = cstruct().load(recent_files_def)

RecentFileCacheRecord = TargetRecordDescriptor(
    "windows/recentfilecache",
    [
        ("path", "path"),
    ],
)


class RecentFileCachePlugin(Plugin):
    """Plugin that parses the RecentFileCache.bcf file."""

    def __init__(self, target: Target):
        super().__init__(target)
        self._recentfiles = self.target.fs.path("sysvol/windows/appcompat/programs/RecentFileCache.bcf")

    def check_compatible(self) -> None:
        if not self._recentfiles.exists():
            raise UnsupportedPluginError("Could not load RecentFileCache.bcf")

    @export(record=RecentFileCacheRecord)
    def recentfilecache(self) -> Iterator[RecentFileCacheRecord]:
        """Parse RecentFileCache.bcf.

        Yields RecentFileCacheRecords with fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            path (uri): The parsed path.
        """
        fh = self._recentfiles.open()

        c_recent_files.header(fh)
        while True:
            try:
                entry = c_recent_files.entry(fh)
                entry.path = entry.path.rstrip("\x00")

                yield RecentFileCacheRecord(
                    path=self.target.fs.path(entry.path),
                    _target=self.target,
                )
            except EOFError:  # noqa: PERF203
                break
