from io import BytesIO
from types import SimpleNamespace
from uuid import UUID
from unittest.mock import patch

from dissect.target.filesystem import Filesystem
from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.filesystems.fat import FatFilesystem
from dissect.target.filesystems.exfat import ExfatFilesystem
from dissect.target.filesystems.extfs import ExtFilesystem
from tests._utils import absolute_path


class MockFilesystem(Filesystem):
    __type__ = "test"


dummy_fh = BytesIO(b"")  # empty in-memory file handle


def test_filesystem_uuid_from_volume_guid():
    """Filesystem.uuid returns a UUID when volume.guid is set."""
    guid_bytes = b"\x01" * 16
    volume = SimpleNamespace(guid=guid_bytes)

    fs = MockFilesystem()
    fs.volume = volume

    assert fs.uuid == UUID(bytes_le=guid_bytes)


def test_filesystem_uuid_none_when_no_guid():
    """Filesystem.uuid returns None when volume.guid is None."""
    volume = SimpleNamespace(guid=None)

    fs = MockFilesystem()
    fs.volume = volume

    assert fs.uuid is None


def test_ntfs_uuid_from_volume_guid():
    """NTFS filesystem UUID is derived correctly from volume GUID."""
    guid_bytes = b"\x01" * 16
    volume = SimpleNamespace(guid=guid_bytes)

    fs = NtfsFilesystem()
    fs.volume = volume

    assert fs.uuid == UUID(bytes_le=guid_bytes)


def test_ntfs_uuid_no_guid():
    """NTFS.uuid falls back to serial when volume.guid is None."""
    serial_number = 123456789
    volume = SimpleNamespace(guid=None)
    fs = NtfsFilesystem()
    fs.volume = volume
    fs.ntfs = SimpleNamespace(serial=serial_number)

    expected_uuid = UUID(int=serial_number)
    assert fs.uuid == expected_uuid


def test_fat_uuid_no_guid():
    """FAT.uuid fallback using fatfs.volume_id when volume.guid is None."""
    volume = SimpleNamespace(guid=None)
    with patch("dissect.target.filesystems.fat.FatFilesystem.__init__", lambda self, fh: None):
        fs = FatFilesystem(fh=dummy_fh)
        fs.volume = volume
        fs.fatfs = SimpleNamespace(volume_id="1a2b3c4d")

        expected_uuid = UUID(int=0x1A2B3C4D)
        assert fs.uuid == expected_uuid


def test_exfat_uuid_no_guid():
    """ExFAT.uuid fallback using exfat.vbr.volume_serial when volume.guid is None."""
    volume = SimpleNamespace(guid=None)
    with patch("dissect.target.filesystems.exfat.ExfatFilesystem.__init__", lambda self, fh: None):
        fs = ExfatFilesystem(fh=dummy_fh)
        fs.volume = volume
        fs.exfat = SimpleNamespace(vbr=SimpleNamespace(volume_serial=987654321))

        expected_uuid = UUID(int=987654321)
        assert fs.uuid == expected_uuid


def test_ext_uuid_no_guid():
    """EXT.uuid fallback using extfs.uuid when volume.guid is None."""
    volume = SimpleNamespace(guid=None)
    fs = ExtFilesystem(fh=absolute_path("_data/filesystems/symlink_disk.ext4").open("rb"))
    fs.volume = volume
    fs.extfs = SimpleNamespace(uuid="e0c3d987-a36c-4f9e-9b2f-90e633d7d7a1")

    expected_uuid = "e0c3d987-a36c-4f9e-9b2f-90e633d7d7a1"
    assert fs.uuid == expected_uuid
