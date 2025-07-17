from __future__ import annotations

import zipfile
from collections import defaultdict
from typing import TYPE_CHECKING

from dissect.target.filesystem import LayerFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.filesystems.zip import ZipFilesystem
from dissect.target.helpers import loaderutil
from dissect.target.loader import Loader
from dissect.target.plugin import OperatingSystem

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target

PREFIXES = ["", "fs"]


class DirLoader(Loader):
    """Load a directory as a filesystem."""

    @staticmethod
    def detect(path: Path) -> bool:
        return find_entry_path(path) is not None

    def map(self, target: Target) -> None:
        path = self.absolute_path.joinpath(find_entry_path(self.absolute_path))
        find_and_map_dirs(target, path)


def find_entry_path(path: Path) -> str | None:
    for prefix in PREFIXES:
        if find_dirs(path / prefix)[0] is not None:
            return prefix
    return None


def map_dirs(
    target: Target,
    dirs: list[Path | tuple[str, Path]],
    os_type: str,
    *,
    dirfs: type[DirectoryFilesystem] = DirectoryFilesystem,
    zipfs: type[ZipFilesystem] = ZipFilesystem,
    **kwargs,
) -> None:
    """Map directories as filesystems into the given target.

    Args:
        target: The target to map into.
        dirs: The directories to map as filesystems. If a list member is a tuple, the first element is the drive letter.
        os_type: The operating system type, used to determine how the filesystem should be mounted.
        dirfs: The filesystem class to use for directory filesystems.
        zipfs: The filesystem class to use for ZIP filesystems.
    """
    alt_separator = ""
    case_sensitive = True
    if os_type == OperatingSystem.WINDOWS:
        alt_separator = "\\"
        case_sensitive = False

    drive_letter_map = defaultdict(list)
    for path in dirs:
        drive_letter = None
        if isinstance(path, tuple):
            drive_letter, path = path
        elif is_drive_letter_path(path):
            drive_letter = path.name[0]

        if isinstance(path, zipfile.Path):
            dfs = zipfs(path.root.fp, path.at, alt_separator=alt_separator, case_sensitive=case_sensitive)
        else:
            dfs = dirfs(path, alt_separator=alt_separator, case_sensitive=case_sensitive)

        drive_letter_map[drive_letter].append(dfs)

    fs_to_add = []
    for drive_letter, dfs in drive_letter_map.items():
        if drive_letter is not None:
            if len(dfs) > 1:
                vfs = LayerFilesystem()
                for fs in dfs:
                    vfs.append_fs_layer(fs)
            else:
                vfs = dfs[0]

            fs_to_add.append(vfs)
            target.fs.mount(drive_letter.lower() + ":", vfs)
        else:
            fs_to_add.extend(dfs)

    for fs in fs_to_add:
        target.filesystems.add(fs)
        if os_type == OperatingSystem.WINDOWS:
            loaderutil.add_virtual_ntfs_filesystem(target, fs, **kwargs)


def find_and_map_dirs(target: Target, path: Path, **kwargs) -> None:
    """Try to find and map directories as filesystems into the given target.

    Args:
        target: The target to map into.
        path: The path to map from.
            If path is a local path, must be provided as an absolute path in order to work with ``target-mount``.
        **kwargs: Optional arguments for :func:`loaderutil.add_virtual_ntfs_filesystem
            <dissect.target.helpers.loaderutil.add_virtual_ntfs_filesystem>`.
    """
    os_type, dirs = find_dirs(path)

    map_dirs(target, dirs, os_type, **kwargs)


def find_dirs(path: Path) -> tuple[str, list[Path]]:
    """Try to find if ``path`` contains an operating system directory layout and return the OS type and detected
    directories.

    In the case of a Windows layout, try to find if there are directories for each drive letter and return
    them all.

    Args:
        path: The path to check.

    Returns:
        A tuple consisting of the found operating system layout and a list of all detected directories.
    """
    dirs = []
    os_type = None

    if path.is_dir():
        for p in path.iterdir():
            # Look for directories like C or C:
            if p.is_dir() and (is_drive_letter_path(p) or p.name in ("sysvol", "$rootfs$")):
                dirs.append(p)

                if not os_type:
                    os_type = os_type_from_path(p)

        if not os_type:
            os_type = os_type_from_path(path)
            dirs = [path]

    return os_type, dirs


def os_type_from_path(path: Path) -> OperatingSystem:
    """Try to detect what kind of operating system directory structure ``path`` contains.

    The operating system type is returned as a string.

    Args:
        path: The path to check.

    Returns:
        The detected operating system type.
    """
    if path.is_dir():
        dirlist = [p.name for p in path.iterdir()]
        dirlist_l = [e.lower() for e in dirlist]

        if "windows" in dirlist_l:
            windows_idx = dirlist_l.index("windows")
            windows_path = path.joinpath(dirlist[windows_idx])
            system32_exists = "system32" in [e.name.lower() for e in windows_path.iterdir()]
        else:
            system32_exists = False

        winnt_exists = "winnt" in dirlist_l

        if system32_exists or winnt_exists:  # Windows
            return OperatingSystem.WINDOWS

        etc_exists = "etc" in dirlist
        var_exists = "var" in dirlist
        library_exists = "Library" in dirlist

        if etc_exists and var_exists and not library_exists:  # Linux
            return OperatingSystem.LINUX

        if library_exists:  # OSX
            return OperatingSystem.OSX

    return None


def is_drive_letter_path(path: Path) -> bool:
    """Check if a path can be a drive letter, e.g. ``C`` or ``C:``.

    Args:
        path: The path to check.

    Returns:
        ``True`` if the path can be interpreted as a drive letter or ``False`` if it can't.
    """
    return len(path.name) == 1 or (len(path.name) == 2 and path.name[1] == ":")
