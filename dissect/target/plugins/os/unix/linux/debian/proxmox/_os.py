from __future__ import annotations

import re
import logging
from io import BytesIO
from typing import Optional

from dissect.sql import sqlite3

from dissect.target.filesystem import Filesystem, VirtualFilesystem
from dissect.target.plugins.os.unix._os import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.target import Target

log = logging.getLogger(__name__)

PROXMOX_PACKAGE_NAME="proxmox-ve"
FILETREE_TABLE_NAME="tree"
PMXCFS_DATABASE_PATH="/var/lib/pve-cluster/config.db"


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
        # [PERSONAL TO REMOVE] Modifies target / executescode before initializing the class
        pmxcfs = _create_pmxcfs(sysvol.path(PMXCFS_DATABASE_PATH).open("rb"))
        target.fs.mount("/etc/pve", pmxcfs)

        ipdb.set_trace()

        return obj

    @export(property=True)
    def version(self) -> str:
            """Returns Proxmox VE version with underlying os release"""

            for pkg in self.target.dpkg.status():
                if pkg.name == PROXMOX_PACKAGE_NAME:
                    distro_name = self._os_release.get("PRETTY_NAME", "")
                    return f"{pkg.name} {pkg.version} ({distro_name})"

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.PROXMOX.value

def _create_pmxcfs(fh):
    db = sqlite3.SQLite3(fh)
    filetree_table = db.table(FILETREE_TABLE_NAME)
    # columns = filetree_table.columns  # For implementing fs with propper stat data later
    rows = filetree_table.rows()

    fs_entries = []
    for row in rows:
        fs_entries.append(row)
    fs_entries.sort(key=lambda entry: (entry.parent, entry.inode), reverse=True)

    vfs = VirtualFilesystem()
    for entry in fs_entries: # might add dir mapping if deemed necessary 
        if entry.type == 8: # Type 8 file | Type 4 dir
            path = entry.name
            parent = entry.parent
            content = entry.data

            for file in fs_entries:
                if file.inode == parent and file.inode != 0:
                    path = f"{file.name}/{path}"
                else:
                    vfs.map_file_fh(f"/{path}", BytesIO(content or b""))

    return  vfs

def _parse_vm_configuration(conf) -> list:
    file = conf.open()
    parsed_lines = {}
    for line in file:
        key, value = line.split(b': ')
        parsed_lines[key] = value.replace(b'\n', b'')
    return parsed_lines

def _is_disk(config_value: str) -> str | None:
    disk = re.match(r"^(sata|scsi|ide)[0-9]+$", config_value)
    return True if disk else None 

def _get_disk_name(config_value: str) -> str | None:
    disk = re.search(r"vm-[0-9]+-disk-[0-9]+", config_value)
    return disk if disk else None