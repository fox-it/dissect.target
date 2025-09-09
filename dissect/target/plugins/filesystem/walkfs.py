from __future__ import annotations

import stat
from typing import TYPE_CHECKING, Union

from dissect.util.ts import from_unix
from typing_extensions import get_args

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.filesystem import FilesystemEntry, LayerFilesystemEntry
from dissect.target.helpers.lazy import import_lazy
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export
from dissect.target.plugins.filesystem.unix.capability import parse_entry as parse_capability_entry

CapabilityRecord = import_lazy("dissect.target.plugins.filesystem.unix.capability").CapabilityRecord
SuidRecord = import_lazy("dissect.target.plugins.filesystem.unix.suid").SuidRecord

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
        ("boolean", "is_suid"),
        ("string[]", "attr"),
        ("string[]", "fs_types"),
    ],
)

WalkFsRecord = Union[FilesystemRecord, SuidRecord, CapabilityRecord]


class WalkFsPlugin(Plugin):
    """Filesystem agnostic walkfs plugin."""

    def check_compatible(self) -> None:
        if not len(self.target.filesystems):
            raise UnsupportedPluginError("No filesystems to walk")

    @export(record=get_args(WalkFsRecord))
    @arg("--walkfs-path", default="/", help="path to recursively walk")
    @arg("--suid", action="store_true", help="output suid records")
    @arg("--capability", action="store_true", help="output capability records")
    def walkfs(self, walkfs_path: str = "/", suid: bool = False, capability: bool = False) -> Iterator[WalkFsRecord]:
        """Walk a target's filesystem and return all filesystem entries.

        Can return additional SUID and Capability records when given ``--suid`` and/or ``--capability`` arguments.

        Filesystems can set extended attributes (``xattr``) on filesystem entries.

        References:
            - https://man7.org/linux/man-pages/man2/lstat.2.html
            - https://man7.org/linux/man-pages/man7/inode.7.html
            - https://man7.org/linux/man-pages/man7/xattr.7.html
            - https://man7.org/linux/man-pages/man2/execve.2.html
            - https://steflan-security.com/linux-privilege-escalation-suid-binaries/
            - https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h

        Yields FilesystemRecords and optionally SuidRecords and CapabilityRecords.

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            mtime (datetime): modified timestamp indicates the last time the contents of a file were modified.
            atime (datetime): access timestamp indicates the last time a file was accessed.
            ctime (datetime): changed timestamp indicates the last time metadata of a file was modified.
            btime (datetime): birth timestamp indicates the time when a file was created.
            ino (varint): number of the corresponding underlying filesystem inode.
            path (path): path location of the entry.
            size (filesize): size of the file in bytes on the filesystem.
            mode (uint32): contains the file type and mode.
            uid (uint32): the user id of the owner of the entry.
            gid (uint32): the group id of the owner of the entry.
            is_suid (boolean): denotes if the entry has the set-user-id bit set.
            attr (string[]): list of key-value pair attributes separated by '='.
            fs_types (string[]): list of filesystem type(s) of the entry.
        """

        path = self.target.fs.path(walkfs_path)

        if not path.exists():
            self.target.log.error("No such directory: '%s'", walkfs_path)
            return

        if not path.is_dir():
            self.target.log.error("Not a directory: '%s'", walkfs_path)
            return

        for entry in self.target.fs.recurse(walkfs_path):
            try:
                yield from generate_record(self.target, entry, suid, capability)

            except FileNotFoundError as e:  # noqa: PERF203
                self.target.log.warning("File not found: %s", entry)
                self.target.log.debug("", exc_info=e)
            except Exception as e:
                self.target.log.warning("Exception generating walkfs record for %s: %s", entry, e)
                self.target.log.debug("", exc_info=e)
                continue


def generate_record(target: Target, entry: FilesystemEntry, suid: bool, capability: bool) -> Iterator[WalkFsRecord]:
    """Generate a :class:`WalkFsRecord` from the given :class:`FilesystemEntry`.

    Args:
        target: :class:`Target` instance
        entry: :class:`FilesystemEntry` instance

    Returns:
        Generator of :class:`WalkFsRecord` for the given :class:`FilesystemEntry`.
    """
    entry_stat = entry.lstat()

    if isinstance(entry, LayerFilesystemEntry):
        fs_types = [sub_entry.fs.__type__ for sub_entry in entry.entries]
    else:
        fs_types = [entry.fs.__type__]

    XATTR_CAPABLE = any(fs for fs in fs_types if fs in ("extfs", "xfs"))

    is_suid = bool(entry_stat.st_mode & stat.S_ISUID)

    fields = {
        "atime": from_unix(entry_stat.st_atime),
        "mtime": from_unix(entry_stat.st_mtime),
        "ctime": from_unix(entry_stat.st_ctime),
        "btime": from_unix(entry_stat.st_birthtime) if entry_stat.st_birthtime else None,
        "ino": entry_stat.st_ino,
        "path": entry.path,
        "size": entry_stat.st_size,
        "mode": entry_stat.st_mode,
        "uid": entry_stat.st_uid,
        "gid": entry_stat.st_gid,
        "is_suid": is_suid,
        "fs_types": fs_types,
    }

    if XATTR_CAPABLE:
        try:
            fields["attr"] = [f"{attr.name}={attr.value.hex()}" for attr in entry.lattr()]
        except Exception as e:
            target.log.warning("Unable to expand xattr for entry %s: %s", entry.path, e)
            target.log.debug("", exc_info=e)

    yield FilesystemRecord(
        **fields,
        _target=target,
    )

    if suid and is_suid:
        yield SuidRecord(
            **fields,
            _target=target,
        )

    if capability and XATTR_CAPABLE and fields.get("attr"):
        yield from parse_capability_entry(entry, target)
