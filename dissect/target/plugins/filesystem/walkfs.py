from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from dissect.util.ts import from_unix

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.filesystem import Filesystem, FilesystemEntry, LayerFilesystemEntry
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export, internal

if TYPE_CHECKING:
    from collections.abc import Iterator

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
        ("string[]", "vuuid"),
        ("string[]", "dserial"),
    ],
)


class WalkFSPlugin(Plugin):
    """Filesystem agnostic walkfs plugin."""

    def check_compatible(self) -> None:
        if not len(self.target.filesystems):
            raise UnsupportedPluginError("No filesystems to walk")

    @export(record=FilesystemRecord)
    @arg("--walkfs-path", default="/", help="path to recursively walk")
    def walkfs(self, walkfs_path: str = "/") -> Iterator[FilesystemRecord]:
        """Walk a target's filesystem and return all filesystem entries."""

        path = self.target.fs.path(walkfs_path)

        if not path.exists():
            self.target.log.error("No such directory: '%s'", walkfs_path)
            return

        if not path.is_dir():
            self.target.log.error("Not a directory: '%s'", walkfs_path)
            return

        for entry in self.target.fs.recurse(walkfs_path):
            try:
                yield generate_record(self.target, entry)

            except FileNotFoundError as e:  # noqa: PERF203
                self.target.log.warning("File not found: %s", entry)
                self.target.log.debug("", exc_info=e)
            except Exception as e:
                self.target.log.warning("Exception generating record for: %s", entry)
                self.target.log.debug("", exc_info=e)
                continue


def get_volume_uuid(entry: Filesystem) -> UUID | None:
    """
    Returns the volume_uuid if it exists. otherwise, returns none

    Args:
        entry: :class:`Filesystem` instance

    Returns:
        UUID as str
    """
    if entry.volume is None:
        return None
    if entry.volume.guid:
        return UUID(bytes_le=entry.volume.guid)
    if entry.__type__ == "ntfs":
        return UUID(int=entry.ntfs.serial)
    if entry.__type__ in ["ext2", "ext3", "ext4"]:
        return entry.extfs.uuid
    if entry.__type__ == "fat":
        return UUID(int=int(entry.fatfs.volume_id, 16))
    if entry.__type__ == "exfat":
        return UUID(int=entry.exfat.vbr.volume_serial)
    # Return None if no valid UUID or serial is found
    return None


@internal
def get_disk_serial(entry: Filesystem) -> str | None:
    """
    Returns the disk_serial if it exists. otherwise, returns none

    Args:
    entry: :class:`Filesystem` instance

    Returns:
        serial as str
    """
    if entry.volume is None:
        return None

    if hasattr(entry.volume.vs, "serial"):
        return entry.volume.vs.serial
    return None


def generate_record(target: Target, entry: FilesystemEntry) -> FilesystemRecord:
    """Generate a :class:`FilesystemRecord` from the given :class:`FilesystemEntry`.

    Args:
        target: :class:`Target` instance
        entry: :class:`FilesystemEntry` instance

    Returns:
        Generated :class:`FilesystemRecord` for the given :class:`FilesystemEntry`.
    """
    stat = entry.lstat()

    if isinstance(entry, LayerFilesystemEntry):
        fs_types = []
        volume_uuids = []
        disk_serials = []

        for sub_entry in entry.entries:
            fs_types.append(sub_entry.fs.__type__)
            volume_uuids.append(get_volume_uuid(sub_entry.fs))
            disk_serials.append(get_disk_serial(sub_entry).fs)

    else:
        fs_types = [entry.fs.__type__]
        volume_uuids = [get_volume_uuid(entry).fs]
        disk_serials = [get_disk_serial(entry).fs]

    return FilesystemRecord(
        atime=from_unix(stat.st_atime),
        mtime=from_unix(stat.st_mtime),
        ctime=from_unix(stat.st_ctime),
        btime=from_unix(stat.st_birthtime) if stat.st_birthtime else None,
        ino=stat.st_ino,
        path=entry.path,
        size=stat.st_size,
        mode=stat.st_mode,
        uid=stat.st_uid,
        gid=stat.st_gid,
        fstypes=fs_types,
        vuuid=volume_uuids,
        dserial=disk_serials,
        _target=target,
    )
