from dissect import cstruct
from flow.record.fieldtypes import path

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

c_recent_files_def = """
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
c_recent_files = cstruct.cstruct()
c_recent_files.load(c_recent_files_def)

RecentFileCacheRecord = TargetRecordDescriptor(
    "windows/recentfilecache",
    [
        ("path", "path"),
    ],
)


class RecentFileCachePlugin(Plugin):
    """Plugin that parses the RecentFileCache.bcf file."""

    def __init__(self, target):
        super().__init__(target)
        self._recentfiles = self.target.fs.path("sysvol/windows/appcompat/programs/RecentFileCache.bcf")

    def check_compatible(self) -> None:
        if not self._recentfiles.exists():
            raise UnsupportedPluginError("Could not load RecentFileCache.bcf")

    @export(record=RecentFileCacheRecord)
    def recentfilecache(self):
        """Parse RecentFileCache.bcf.

        Yields RecentFileCacheRecords with fields:
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
                    path=path.from_windows(entry.path),
                    _target=self.target,
                )
            except EOFError:
                break
