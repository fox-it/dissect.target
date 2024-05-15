from __future__ import annotations

import os
import re
import pathlib
import logging
from io import BytesIO
from typing import Optional

from dissect.sql import sqlite3

from dissect.target.filesystem import Filesystem, VirtualFilesystem
from dissect.target.plugins.os.unix._os import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.target import Target

import ipdb

log = logging.getLogger(__name__)

PROXMOX_PACKAGE_NAME="proxmox-ve"
FILETREE_TABLE_NAME="tree"
PMXCFS_DATABASE_PATH="/var/lib/pve-cluster/config.db"
# VM_CONFIG_PATH="/etc/pve/qemu-server" # TODO: Change to /etc/pve/nodes/pve/qemu-server once pmxcfs func has been reworked to properly map fs
VM_CONFIG_PATH="/etc/pve/" # TODO: properly implement pmxcfs creation and revert to propper path


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
        configs = self.target.fs.path(VM_CONFIG_PATH)
        for config in configs.iterdir():
            if pathlib.Path(config).suffix == ".conf": # TODO: Remove if statement once pmxcfs is propperly implemented
                yield VirtualMachineRecord(
                    id=pathlib.Path(config).stem,
                    config_path=config,
                )

def _create_pmxcfs(fh) -> VirtualFilesystem:
    db = sqlite3.SQLite3(fh)
    filetree_table = db.table(FILETREE_TABLE_NAME)
    rows = filetree_table.rows()
    fs_entries = []
    for row in rows:
        fs_entries.append(row)
    fs_entries.sort(key=lambda entry: (entry.parent, entry.inode))

    vfs = VirtualFilesystem()
    for entry in fs_entries:
        content = entry.data
        if entry.parent == 0: # Root entries do not require parent check
            vfs.map_file_fh(f"/{entry.name}",  BytesIO(content or b""))
            continue
        else:
            entry_chain = _get_entry_parent_chain(fs_entries, entry)
            path = _create_fs_path(entry_chain)
            vfs.map_file_fh(f"{path}", BytesIO(content or b"")) # TODO: revert root (/) on string once pmxcfs has been propperly implemented

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
