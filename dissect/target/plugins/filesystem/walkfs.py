from dissect.util.ts import from_unix

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export, internal

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
        ("string", "fstype"),
        ("uint32", "fsidx"),
    ],
)


class WalkFSPlugin(Plugin):
    def check_compatible(self) -> None:
        if not len(self.target.filesystems):
            raise UnsupportedPluginError("No filesystems found")

    @export(record=FilesystemRecord)
    def walkfs(self):
        """Walk a target's filesystem and return all filesystem entries."""
        for _, record in self.walkfs_ext():
            yield record

    @internal
    def walkfs_ext(self, root="/", pattern="*"):
        for idx, fs in enumerate(self.target.filesystems):
            for entry in fs.path(root).rglob(pattern):
                try:
                    yield entry, generate_record(self.target, entry, idx)
                except FileNotFoundError:
                    continue
                except Exception:
                    self.target.log.exception("Failed to generate record from entry %s", entry)


def generate_record(target, entry, idx):
    stat = entry.lstat()
    return FilesystemRecord(
        atime=from_unix(stat.st_atime),
        mtime=from_unix(stat.st_mtime),
        ctime=from_unix(stat.st_ctime),
        ino=stat.st_ino,
        path=entry,
        size=stat.st_size,
        mode=stat.st_mode,
        uid=stat.st_uid,
        gid=stat.st_gid,
        fstype=entry.get().fs.__fstype__,
        fsidx=idx,
        _target=target,
    )
