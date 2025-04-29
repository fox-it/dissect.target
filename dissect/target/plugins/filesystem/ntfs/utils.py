from __future__ import annotations

import re
from enum import Enum, auto
from typing import TYPE_CHECKING
from uuid import UUID

from dissect.ntfs.exceptions import FileNotFoundError

if TYPE_CHECKING:
    from dissect.ntfs.mft import MftRecord

    from dissect.target.filesystems.ntfs import NtfsFilesystem
    from dissect.target.target import Target

DRIVE_LETTER_RE = re.compile(r"[a-zA-Z]:")


class InformationType(Enum):
    """Valid information types."""

    STANDARD_INFORMATION = auto()
    FILE_INFORMATION = auto()
    ALTERNATE_DATA_STREAM = auto()


def get_drive_letter(target: Target, filesystem: NtfsFilesystem) -> str:
    """Retrieve the drive letter from the loaded mounts

    When the drive letter is not available for that filesystem it returns empty.
    """
    # A filesystem can be known under multiple drives (mount points). If it is
    # a windows system volume, there are the default sysvol and c: drives.
    # If the target has a virtual ntfs filesystem, e.g. as constructed by the
    # tar and dir loaders, there is also the /$fs$/fs<n> drive, under which the
    # "fake" ntfs filesystem is mounted.
    # The precedence for drives is first the drive letter drives (e.g. c:),
    # second the "normally" named drives (e.g. sysvol) and finally the anonymous
    # drives (e.g. /$fs/fs0).
    mount_items = (item for item in target.fs.mounts.items() if hasattr(item[1], "ntfs"))
    drives = [key for key, fs in mount_items if fs.ntfs is filesystem.ntfs]

    single_letter_drives = []
    other_drives = []
    anon_drives = []

    for drive in drives:
        if DRIVE_LETTER_RE.match(drive):
            single_letter_drives.append(drive)
        elif "$fs$" in drive:
            anon_drives.append(drive)
        else:
            other_drives.append(drive)

    drives = sorted(single_letter_drives) + sorted(other_drives) + sorted(anon_drives)

    if drives:
        return f"{drives[0]}\\"
    return ""


def get_volume_identifier(fs: NtfsFilesystem) -> str | None:
    """Return the filesystem GUID if available."""
    try:
        return f"{UUID(bytes_le=fs.volume.guid)}"
    except (AttributeError, TypeError, ValueError):
        # AttributeError is raised when volume is None
        # TypeError is raised when guid is None
        # ValueError is raised when the guid string is smaller than 16 bytes
        return None


def get_owner_and_group(entry: MftRecord, fs: NtfsFilesystem) -> tuple[str | None, str | None]:
    owner, group = None, None
    try:
        stdinfo = entry.attributes.STANDARD_INFORMATION[0]
        sd = fs.ntfs.secure.lookup(stdinfo.security_id)
        owner, group = sd.owner, sd.group
    except (AttributeError, IndexError, KeyError):
        # When $STANDARD_INFORMATION cannot be found or no $Secure file is loaded
        pass
    return owner, group


def get_record_size(record: MftRecord, name: str = "") -> int | None:
    """Gets the size for a specific record."""
    try:
        return record.size(name)
    except (FileNotFoundError, KeyError):
        # FileNotFoundError is raised when the entry has no attributes
        # KeyError is raised when it tries to access a specific attribute that does not exist
        pass
    return None
