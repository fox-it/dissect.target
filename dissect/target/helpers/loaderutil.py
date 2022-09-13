import re
import urllib.parse
from os import PathLike
from pathlib import Path
from typing import Optional, Union

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.loader import Loader, LOADERS_BY_SCHEME


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


def parse_path_uri(path: Union[str, Path]) -> tuple[Optional[Path], Optional[Loader], dict, str]:
    """Converts a path string into a path while taking URIs into account.

    If the path string contains an URI the scheme will be used to infer
    the loader by using the ``LOADERS_BY_SCHEME`` dict. In case of an URI
    the path will be set to the remainder of the string (including
    host and port) to form a pseudo path that can easily be used by
    URI-based loaders.

    If no loader can be inferred, the loader will be set to None
    and the default detection mechanisms of the caller should proceed,
    this should also apply to the 'file://' and 'raw://' schemes.

    Additionally to remain backward compatible with the previous version
    of this function, the scheme string and query parameters will be returned.
    The scheme string will be returned even if the loader has not been
    inferred.

    Args:
        path: String describing the path of a target or Path.

    Returns:
        A tuple containing:
        - a Path object (wrapped around the provided path string)
        - the inferred loader or None
        - query parameters (always a dict)
        - scheme string if any (or an empty string)
    """

    if path is None:
        return None, None, {}, ""

    parsed_path = urllib.parse.urlparse(str(path))
    parsed_query = urllib.parse.parse_qs(parsed_path.query, keep_blank_values=True)

    # Then, always it got wrapped in a Path if it was something else (backward compat)
    if not isinstance(path, PathLike):
        path = Path(path)

    # if we have no scheme or it's invalid (or a Windows drive letter),
    # return the path and the parsed query (backward compat)
    if parsed_path.scheme == "" or re.match("^[A-Za-z]$", parsed_path.scheme):
        return path, None, parsed_query, ""

    # Otherwise use the scheme to infer the loader
    inferred_loader = LOADERS_BY_SCHEME.get(parsed_path.scheme)

    # also create a useful 'pseudo path' for pragmatic purposes to use as URL
    return Path(f"{parsed_path.netloc}{parsed_path.path}"), inferred_loader, parsed_query, parsed_path.scheme
