from io import BytesIO
from unittest.mock import Mock, patch

from dissect.target.filesystem import Filesystem
from dissect.target.filesystems.exfat import ExfatFilesystem
from dissect.target.filesystems.extfs import ExtFilesystem
from dissect.target.filesystems.fat import FatFilesystem
from dissect.target.filesystems.ntfs import NtfsFilesystem
from tests._utils import absolute_path


class MockFilesystem(Filesystem):
    __type__ = "test"


def test_filesystem_identifier_from_volume_guid() -> None:
    """Filesystem.identifier returns a string when volume.guid is set."""
    guid = "test" * 4

    fs = MockFilesystem()
    fs.volume = Mock(guid=guid)

    assert fs.identifier == guid


def test_filesystem_identifier_string_when_no_guid() -> None:
    """Filesystem.identifier returns the volume name when volume.guid is None."""

    fs = MockFilesystem()
    fs.volume = Mock(guid=None)
    fs.volume.name = "TestVolume"

    assert fs.identifier == "TestVolume"


def test_filesystem_identifier_string_when_no_guid_or_name() -> None:
    """Filesystem.identifier returns the fs type name when volume.guid and volume name are None."""

    fs = MockFilesystem()
    fs.volume = Mock(guid=None)
    fs.volume.name = None

    assert fs.identifier == "filesystem_test"


def test_ntfs_identifier_from_volume_guid() -> None:
    """NTFS filesystem identifier is derived correctly from volume GUID."""
    guid = "test" * 4
    volume = Mock(guid=guid)

    fs = NtfsFilesystem()
    fs.volume = volume

    assert fs.identifier == guid


def test_ntfs_identifier_no_guid() -> None:
    """NTFS.identifier falls back to serial when volume.guid is None."""
    serial_number = "123456789"
    fs = NtfsFilesystem()
    fs.volume = Mock(guid=None)
    fs.ntfs = Mock(serial=serial_number)

    assert fs.identifier == serial_number


def test_fat_identifier_no_guid() -> None:
    """FAT.identifier fallback using fatfs.volume_id when volume.guid is None."""
    dummy_fh = BytesIO(b"")  # empty in-memory file handle
    with patch("dissect.target.filesystems.fat.FatFilesystem.__init__", lambda self, fh: None):
        fs = FatFilesystem(fh=dummy_fh)
        fs.volume = Mock(guid=None)
        fs.fatfs = Mock(volume_id="1a2b3c4d")

        expected_uuid = "439041101"  # in decimal
        assert fs.identifier == expected_uuid


def test_exfat_identifier_no_guid() -> None:
    """ExFAT.identifier fallback using exfat.vbr.volume_serial when volume.guid is None."""
    dummy_fh = BytesIO(b"")  # empty in-memory file handle
    with patch("dissect.target.filesystems.exfat.ExfatFilesystem.__init__", lambda self, fh: None):
        fs = ExfatFilesystem(fh=dummy_fh)
        fs.volume = Mock(guid=None)
        fs.exfat = Mock(vbr=Mock(volume_serial=987654321))

        expected_uuid = "987654321"
        assert fs.identifier == expected_uuid


def test_ext_identifier_no_guid() -> None:
    """EXT.identifier fallback using extfs.identifier when volume.guid is None."""
    fs = ExtFilesystem(fh=absolute_path("_data/filesystems/symlink_disk.ext4").open("rb"))
    fs.volume = Mock(guid=None)
    fs.extfs = Mock(uuid="e0c3d987-a36c-4f9e-9b2f-90e633d7d7a1")

    expected_uuid = "e0c3d987-a36c-4f9e-9b2f-90e633d7d7a1"
    assert fs.identifier == expected_uuid
