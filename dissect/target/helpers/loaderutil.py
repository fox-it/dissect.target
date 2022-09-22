import re
import urllib

from typing import Optional, Tuple, Union
from pathlib import Path
from os import PathLike

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystems.ntfs import NtfsFilesystem


def add_virtual_ntfs_filesystem(
    target,
    fs,
    boot_path="$Boot",
    mft_path="$MFT",
    usnjrnl_path="$Extend/$Usnjrnl:$J",
    sds_path="$Secure:$SDS",
):
    """Utility for creating an NtfsFilesystem with separate system files from another Filesystem, usually
    a DirectoryFilesystem or VirtualFilesystem.

    Args:
        target: The target to add the filesystem to.
        fs: The Filesystem to load the system files from.
        boot_path: Path to open the $Boot file from.
        mft_path: Path to open the $MFT file from.
        usnjrnl_path: Path to open the $Usnjrnl:$J file from.
        sds_path: Path to open the $Secure:$SDS file from.
    """
    fh_boot = _try_open(fs, boot_path)
    fh_mft = _try_open(fs, mft_path)
    fh_usnjrnl = _try_open(fs, usnjrnl_path)
    fh_sds = _try_open(fs, sds_path)

    if any([fh_boot, fh_mft]):
        ntfs = NtfsFilesystem(boot=fh_boot, mft=fh_mft, usnjrnl=fh_usnjrnl, sds=fh_sds)
        target.filesystems.add(ntfs)
        fs.ntfs = ntfs.ntfs


def _try_open(fs, path):
    paths = [path] if not isinstance(path, list) else path

    for path in paths:
        try:
            return fs.open(path)
        except FileNotFoundError:
            pass


def extract_path_info(path: Union[str, Path]) -> Tuple[Path, Optional[urllib.parse.ParseResult]]:

    """
    Extracts a ParseResult from a path if it has
    a scheme and adjusts the path if necessary.

    Args:
        path: String or Path describing the path of a target.

    Returns:
        - a Path or None
        - ParseResult or None

    """

    if path is None:
        return None, None

    if isinstance(path, PathLike):
        return path, None

    parsed_path = urllib.parse.urlparse(path)
    if parsed_path.scheme == "" or re.match("^[A-Za-z]$", parsed_path.scheme):
        return Path(path), None
    else:
        return Path(parsed_path.path), parsed_path
