from __future__ import annotations

from pathlib import Path
from typing import List, Tuple, TYPE_CHECKING

from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.helpers import loaderutil
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from dissect.target import Target


class DirLoader(Loader):
    @staticmethod
    def detect(path: Path) -> bool:
        return find_dirs(path)[0] is not None

    def map(self, target: Target) -> None:
        map_dirs(target, self.path)


def map_dirs(target: Target, path: Path, **kwargs) -> None:
    """Try to map all found directories as filesystems into the given target.

    Args:
        target: The target to map into.
        path: The path to map from.
        **kwargs: Optional arguments for :func:`loaderutil.add_virtual_ntfs_filesystem
            <dissect.target.helpers.loaderutil.add_virtual_ntfs_filesystem>`.
    """
    os_type, dirs = find_dirs(path)

    alt_separator = ""
    case_sensitive = True
    if os_type == "windows":
        alt_separator = "\\"
        case_sensitive = False

    for path in dirs:
        dfs = DirectoryFilesystem(path, alt_separator=alt_separator, case_sensitive=case_sensitive)
        target.filesystems.add(dfs)

        if os_type == "windows":
            loaderutil.add_virtual_ntfs_filesystem(target, dfs, **kwargs)

            if is_drive_letter_path(path):
                target.fs.mount(path.name[0] + ":", dfs)


def find_dirs(path: Path) -> Tuple[str, List[Path]]:
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
            if p.is_dir() and is_drive_letter_path(p):
                dirs.append(p)

                if not os_type:
                    os_type = os_type_from_path(p)

        if not os_type:
            os_type = os_type_from_path(path)
            dirs = [path]

    return os_type, dirs


def os_type_from_path(path: Path) -> str:
    """Try to detect what kind of operating system directory structure ``path`` contains.

    The operating system type is returned as a string.

    Args:
        path: The path to check.

    Returns:
        The detected operating system type, one of ``windows``, ``linux`` or ``osx``.
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
            return "windows"

        etc_exists = "etc" in dirlist
        var_exists = "var" in dirlist
        library_exists = "Library" in dirlist

        if etc_exists and var_exists and not library_exists:  # Linux
            return "linux"

        if library_exists:  # OSX
            return "osx"

    return None


def is_drive_letter_path(path: Path) -> bool:
    """Check if a path can be a drive letter, e.g. ``C`` or ``C:``.

    Args:
        path: The path to check.

    Returns:
        ``True`` if the path can be interpreted as a drive letter or ``False`` if it can't.
    """
    return len(path.name) == 1 or (len(path.name) == 2 and path.name[1] == ":")
