from __future__ import annotations

import logging
import re
import urllib.parse
from os import PathLike
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystems.ntfs import NtfsFilesystem

if TYPE_CHECKING:
    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target

log = logging.getLogger(__name__)


def add_virtual_ntfs_filesystem(
    target: Target,
    fs: Filesystem,
    boot_path: str = "$Boot",
    mft_path: str = "$MFT",
    usnjrnl_path: str = "$Extend/$Usnjrnl:$J",
    sds_path: str = "$Secure:$SDS",
) -> None:
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
        ntfs = None

        try:
            ntfs = NtfsFilesystem(boot=fh_boot, mft=fh_mft, usnjrnl=fh_usnjrnl, sds=fh_sds)
        except Exception as e:
            if fh_boot:
                log.warning("Failed to load NTFS filesystem from %s, retrying without $Boot file", fs)
                log.debug("", exc_info=e)

                try:
                    # Try once more without the $Boot file
                    ntfs = NtfsFilesystem(mft=fh_mft, usnjrnl=fh_usnjrnl, sds=fh_sds)
                except Exception:
                    log.warning("Failed to load NTFS filesystem from %s without $Boot file, skipping", fs)
                    return

        # Only add it if we have a valid NTFS with an MFT
        if ntfs and ntfs.ntfs.mft:
            target.filesystems.add(ntfs)
            fs.ntfs = ntfs.ntfs
        else:
            log.warning("Opened NTFS filesystem from %s but could not find $MFT, skipping", fs)


def _try_open(fs: Filesystem, path: str) -> BinaryIO | None:
    paths = [path] if not isinstance(path, list) else path

    for path in paths:
        try:
            path = fs.get(path)
            if path.stat().st_size > 0:
                return path.open()
            log.warning("File is empty and will be skipped: %s", path)
        except FileNotFoundError:  # noqa: PERF203
            pass
    return None


def extract_path_info(path: str | Path) -> tuple[Path, urllib.parse.ParseResult | None]:
    """Extracts a ``ParseResult`` from a path if it has a scheme and adjusts the path if necessary.

    Args:
        path: String or ``Path`` describing the path of a target.

    Returns:
        - a ``Path`` or ``None``
        - ``ParseResult`` or ``None``
    """

    if path is None:
        return None, None

    if isinstance(path, PathLike):
        return path, None

    parsed_path = urllib.parse.urlparse(path)
    if parsed_path.scheme == "" or re.match("^[A-Za-z]$", parsed_path.scheme):
        return Path(path), None
    return Path(parsed_path.netloc + parsed_path.path).expanduser(), parsed_path
