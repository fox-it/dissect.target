from __future__ import annotations

import os
import re
import stat
import pathlib
import logging
from io import BytesIO
from typing import Optional

from dissect.sql import sqlite3

from dissect.target.filesystem import Filesystem, VirtualFilesystem, VirtualFile, VirtualDirectory
from dissect.target.helpers import fsutil
from dissect.target.plugins.os.unix._os import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.target import Target


log = logging.getLogger(__name__)

PROXMOX_PACKAGE_NAME="proxmox-ve"
FILETREE_TABLE_NAME="tree"
PMXCFS_DATABASE_PATH="/var/lib/pve-cluster/config.db"
PROXMOX_NODES_PATH="/etc/pve/nodes"


VirtualMachineRecord = TargetRecordDescriptor(
    "proxmox/vm",
    [
        ("string", "id"),
        ("string", "config_path"),
    ],
)


class ProxmoxPlugin(LinuxPlugin):
    def __init__(self, target: Target):
        super().__init__(target)

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        for fs in target.filesystems:
            if (fs.exists("/etc/pve") or fs.exists("/var/lib/pve")):
                return fs
        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> ProxmoxPlugin:
        obj = super().create(target, sysvol)
        pmxcfs = _create_pmxcfs(sysvol.path(PMXCFS_DATABASE_PATH).open("rb"))
        target.fs.mount("/etc/pve", pmxcfs)

        return obj

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.PROXMOX.value

    @export(property=True)
    def version(self) -> str:
        """Returns Proxmox VE version with underlying os release"""

        for pkg in self.target.dpkg.status():
            if pkg.name == PROXMOX_PACKAGE_NAME:
                distro_name = self._os_release.get("PRETTY_NAME", "")
                return f"{pkg.name} {pkg.version} ({distro_name})"

    @export(record=VirtualMachineRecord)
    def vm_list(self) -> Iterator[VirtualMachineRecord]:
        configs = self.target.fs.path(self.vm_configs_path)
        for config in configs.iterdir():
            yield VirtualMachineRecord(
                id=pathlib.Path(config).stem,
                config_path=config,
            )

    @export(property=True)
    def vm_configs_path(self) -> str:
        """Returns path containing VM configurations of the target pve node"""

        return f"{PROXMOX_NODES_PATH}/{self.hostname}/qemu-server"

def _create_pmxcfs(fh) -> VirtualFilesystem:
    db = sqlite3.SQLite3(fh)
    filetree_table = db.table(FILETREE_TABLE_NAME)
    rows = filetree_table.rows()
    fs_entries = {}

    # index entries on their inodes
    for row in rows:
        fs_entries[row.inode] = row

    vfs = VirtualFilesystem()
    for entry in fs_entries.values():
        if entry.parent == 0: # Root entries do not require parent check
            path = entry.name
        else:
            parts = []
            current = entry
            while current.parent != 0:
                parts.append(current.name)
                current = fs_entries[current.parent]
            parts.append(current.name) # appends the missing root parent

            path = "/".join(parts[::-1])
        if entry.type == 4:
            fsentry = ProxmoxConfigDirectoryEntry(vfs, path, entry)
        elif entry.type == 8:
            fsentry = ProxmoxConfigFileEntry(vfs, path, entry)
        else:
            raise ValueError(f"Unknown pmxcfs file type: {entry.type}")

        vfs.map_file_entry(path, fsentry)

    return  vfs

def _get_entry_parent_chain(fs_entries: list, entry: sqlite3[Row]) -> list[sqlite3[Row]]:
    """Looks through the list of inodes (fs_entries) and retrieves parent inode of each node until root is found."""

    inode_chain = [entry]
    target = entry
    for entry in fs_entries:
        if target.inode != 0:
            inode_chain.append(entry)
            target = entry
        else:
            return inode_chain

def _create_fs_path(entry_chain: list[sqlite3[Row]]) -> str:
    """Creates a full path out of a sorted list of file entries"""
    
    entry_chain.sort(key=lambda entry: (entry.parent))
    entry_names = []
    for entry in entry_chain:
        if entry.inode != 0:
            entry_names.append(entry.name)

    path = "/".join(entry_names)

    return path


class ProxmoxConfigFileEntry(VirtualFile):
    def open(self) -> BinaryIO:
        """Returns file handle (file-like object)."""
        # if self.entry is not a directory, but a file
        return BytesIO(self.entry.data or b"")

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        return fsutil.stat_result(
            [
                stat.S_IFREG | 0o777,
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

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        return fsutil.stat_result(
            [
                stat.S_IFDIR | 0o777,
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