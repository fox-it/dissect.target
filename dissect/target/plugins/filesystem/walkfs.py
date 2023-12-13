from typing import Iterable

from dissect.util.ts import from_unix

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.filesystem import RootFilesystemEntry
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.target import Target

FilesystemRecord = TargetRecordDescriptor(
    "filesystem/entry",
    [
        ("datetime", "atime"),
        ("datetime", "mtime"),
        ("datetime", "ctime"),
        ("datetime", "btime"),
        ("varint", "ino"),
        ("path", "path"),
        ("filesize", "size"),
        ("uint32", "mode"),
        ("uint32", "uid"),
        ("uint32", "gid"),
        ("string[]", "fstypes"),
    ],
)


class WalkFSPlugin(Plugin):
    def check_compatible(self) -> None:
        if not len(self.target.filesystems):
            raise UnsupportedPluginError("No filesystems found")

    @export(record=FilesystemRecord)
    def walkfs(self) -> Iterable[FilesystemRecord]:
        """Walk a target's filesystem and return all filesystem entries."""
        for path_entries, _, files in self.target.fs.walk_ext("/"):
            entries = [path_entries[-1]] + files
            for entry in entries:
                path = self.target.fs.path(entry.path)
                try:
                    record = generate_record(self.target, path)
                except FileNotFoundError:
                    continue
                yield record


def generate_record(target: Target, path: TargetPath) -> FilesystemRecord:
    stat = path.lstat()
    btime = from_unix(stat.st_birthtime) if stat.st_birthtime else None
    entry = path.get()
    if isinstance(entry, RootFilesystemEntry):
        fs_types = [sub_entry.fs.__type__ for sub_entry in entry.entries]
    else:
        fs_types = [entry.fs.__type__]
    return FilesystemRecord(
        atime=from_unix(stat.st_atime),
        mtime=from_unix(stat.st_mtime),
        ctime=from_unix(stat.st_ctime),
        btime=btime,
        ino=stat.st_ino,
        path=path,
        size=stat.st_size,
        mode=stat.st_mode,
        uid=stat.st_uid,
        gid=stat.st_gid,
        fstypes=fs_types,
        _target=target,
    )
