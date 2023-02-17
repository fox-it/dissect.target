from enum import Enum, auto
from typing import Optional, Tuple
from uuid import UUID

from dissect.ntfs.exceptions import FileNotFoundError
from dissect.ntfs.mft import MftRecord

from dissect.target import Target
from dissect.target.filesystems.ntfs import NtfsFilesystem


class InformationType(Enum):
    STANDARD_INFORMATION = auto()
    FILE_INFORMATION = auto()
    ALTERNATE_DATA_STREAM = auto()


def get_drive_letter(target: Target, filesystem: NtfsFilesystem):
    """Retrieve the drive letter from the loaded mounts

    When the drive letter is not available for that filesystem it returns empty.
    """
    mount_items = (item for item in target.fs.mounts.items() if hasattr(item[1], "ntfs"))
    driveletters = [key for key, fs in mount_items if fs.ntfs is filesystem.ntfs]

    if driveletters:
        # Currently, mount_dict contain 2 instances of the same filesystem: 'sysvol' and 'c:'
        # This is to choose the latter which will be 'c:'
        return f"{driveletters[-1]}\\"
    else:
        return ""


def get_volume_identifier(fs: NtfsFilesystem) -> str:
    """Return the filesystem guid if available"""
    try:
        return f"{UUID(bytes_le=fs.volume.guid)}"
    except (AttributeError, TypeError, ValueError):
        # AttributeError is raised when volume is None
        # TypeError is raised when guid is None
        # ValueError is raised when the guid string is smaller than 16 bytes
        return None


def get_owner_and_group(entry: MftRecord, fs: NtfsFilesystem) -> Tuple[Optional[str], Optional[str]]:
    owner, group = None, None
    try:
        stdinfo = entry.attributes.STANDARD_INFORMATION[0]
        sd = fs.ntfs.secure.lookup(stdinfo.security_id)
        owner, group = sd.owner, sd.group
    except (AttributeError, IndexError, KeyError):
        # When $STANDARD_INFORMATION cannot be found or no $Secure file is loaded
        pass
    return owner, group


def get_record_size(record: MftRecord, name: str = "") -> Optional[int]:
    """Gets the size for a specific record"""
    try:
        return record.size(name)
    except (FileNotFoundError, KeyError):
        # FileNotFoundError is raised when the entry has no attributes
        # KeyError is raised when it tries to access a specific attribute that does not exist
        pass
    return None
