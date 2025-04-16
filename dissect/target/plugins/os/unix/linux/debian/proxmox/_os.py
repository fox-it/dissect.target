from __future__ import annotations

import stat
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.sql import sqlite3
from dissect.util.stream import BufferedStream

from dissect.target.filesystem import (
    Filesystem,
    VirtualDirectory,
    VirtualFile,
    VirtualFilesystem,
)
from dissect.target.helpers import fsutil
from dissect.target.plugins.os.unix._os import OperatingSystem, export
from dissect.target.plugins.os.unix.linux.debian._os import DebianPlugin

if TYPE_CHECKING:
    from typing_extensions import Self

    from dissect.target.target import Target


class ProxmoxPlugin(DebianPlugin):
    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for fs in target.filesystems:
            if fs.exists("/etc/pve") or fs.exists("/var/lib/pve"):
                return fs

        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        obj = super().create(target, sysvol)

        if (config_db := target.fs.path("/var/lib/pve-cluster/config.db")).exists():
            with config_db.open("rb") as fh:
                vfs = _create_pmxcfs(fh, obj.hostname)

            target.fs.mount("/etc/pve", vfs)

        return obj

    @export(property=True)
    def version(self) -> str:
        """Returns Proxmox VE version with underlying OS release."""

        for pkg in self.target.dpkg.status():
            if pkg.name == "proxmox-ve":
                distro_name = self._os_release.get("PRETTY_NAME", "")
                return f"{pkg.name} {pkg.version} ({distro_name})"
        return None

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.PROXMOX.value


DT_DIR = 4
DT_REG = 8


def _create_pmxcfs(fh: BinaryIO, hostname: str | None = None) -> VirtualFilesystem:
    # https://pve.proxmox.com/wiki/Proxmox_Cluster_File_System_(pmxcfs)
    db = sqlite3.SQLite3(fh)

    entries = {row.inode: row for row in db.table("tree")}

    vfs = VirtualFilesystem()
    for entry in entries.values():
        if entry.type == DT_DIR:
            cls = ProxmoxConfigDirectoryEntry
        elif entry.type == DT_REG:
            cls = ProxmoxConfigFileEntry
        else:
            raise ValueError(f"Unknown pmxcfs file type: {entry.type}")

        parts = []
        current = entry
        while current.parent != 0:
            parts.append(current.name)
            current = entries[current.parent]
        parts.append(current.name)

        path = "/".join(parts[::-1])
        vfs.map_file_entry(path, cls(vfs, path, entry))

    if hostname:
        node_root = vfs.path(f"nodes/{hostname}")
        vfs.symlink(str(node_root), "local")
        vfs.symlink(str(node_root / "lxc"), "lxc")
        vfs.symlink(str(node_root / "openvz"), "openvz")
        vfs.symlink(str(node_root / "qemu-server"), "qemu-server")

    # TODO: .version, .members, .vmlist, maybe .clusterlog and .rrd?

    return vfs


class ProxmoxConfigFileEntry(VirtualFile):
    def open(self) -> BinaryIO:
        return BufferedStream(BytesIO(self.entry.data or b""))

    def lstat(self) -> fsutil.stat_result:
        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        return fsutil.stat_result(
            [
                stat.S_IFREG | 0o640,
                self.entry.inode,
                id(self.fs),
                1,
                0,
                0,
                len(self.entry.data) if self.entry.data else 0,
                0,
                self.entry.mtime,
                0,
            ]
        )


class ProxmoxConfigDirectoryEntry(VirtualDirectory):
    def __init__(self, fs: VirtualFilesystem, path: str, entry: sqlite3.Row):
        super().__init__(fs, path)
        self.entry = entry

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        return fsutil.stat_result(
            [
                stat.S_IFDIR | 0o755,
                self.entry.inode,
                id(self.fs),
                1,
                0,
                0,
                0,
                0,
                self.entry.mtime,
                0,
            ]
        )
