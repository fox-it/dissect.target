from dissect.target.filesystem import LayerFilesystemEntry
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export
from dissect.target.helpers.magic import Magic, from_entry

from collections.abc import Iterator

walkfsRecord = TargetRecordDescriptor(
    "filesystem/mywalkfs/record",
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
        ("string", "mimetype"),
        ("boolean", "is_suid"),
        ("string", "type"),
        ("string[]", "attr"),
        ("string[]", "fs_types"),
        ("string[]", "volume_identifiers"),
    ],
)

class MyWalkPlugin(Plugin):
    def check_compatible(self) -> None:
        pass

    @export(record=walkfsRecord)
    def mywalkfs(
            self,
            path: str = "/",
    ) -> Iterator[walkfsRecord]:
        for file in self.target.fs.recurse(path):
            stat = file.stat()

            mimetype = None #because dirs and symlinks dont have mime type
            type = "Unknown"
            if file.is_symlink():
                type = "Symlink"
            elif file.is_dir():
                type = "Directory"
            elif file.is_file():
                mimetype = from_entry(file)
                type = "File"

            try:
                attr = file.attr() #returns a dict of [string, byte] not quite what i need but im not sure because some functions just return none
            except Exception:
                attr = None

            fs_types = []
            volume_identifiers = []
            if isinstance(file, LayerFilesystemEntry): #layered file system
                for layer in file.fs.layers:
                    fs_types.append(layer.__type__)
                    volume_identifiers.append(layer.identifier)
            else:
                fs_types = [file.fs.__type__]
                volume_identifiers = [file.fs.identifier]




            yield walkfsRecord(
                atime=stat.st_atime,
                mtime=stat.st_mtime,
                ctime=stat.st_ctime,
                btime=stat.st_birthtime,
                ino=stat.st_ino,
                path=self.target.fs.path(file.path),
                size=stat.st_size,
                mode=stat.st_mode,
                uid=stat.st_uid,
                gid=stat.st_gid,
                mimetype=mimetype,
                is_suid=bool(stat.st_mode & 0o4000), #SUID is defined by 4
                type=type,
                attr=attr,
                fs_types=fs_types,
                volume_identifiers=volume_identifiers
            )


