import pytest

from unittest.mock import patch, mock_open

from dissect.target.containers.raw import RawContainer
from dissect.target.loaders.local import _add_disk_as_raw_container_to_target, LINUX_DRIVE_REGEX
from dissect.target.target import TargetLogAdapter

testdata_linux_drive_regex = [
    ("fd0", True),  # Floppy
    ("fd1", True),  # Floppy
    ("fd2", True),  # Floppy
    ("sda", True),  # SCSI
    ("sdb", True),  # SCSI
    ("sdc", True),  # SCSI
    ("sda1", False),  # Partition
    ("nvme0n1", True),  # NVMe Disk
    ("nvme0n1p1", False),  # Partition
    ("hda", True),  # IDE-Controller
    ("hdb", True),  # IDE-Controller
    ("hda1", False),  # Partition
    ("sr0", False),  # Compact Disc
    ("scd0", False),  # Compact Disc
    ("tty11", False),  # Not a disk
    ("xsdaa", False),  # Fake
    ("xhdaa", False),  # Fake
]


def test_local_loader_drive_skipping(mock_target):
    mock = mock_open()
    # Does it attempt to open the file and pass a raw container?
    with (patch("builtins.open", mock), patch.object(mock_target.disks, "add") as mock_method):
        drive = "/xdev/fake"
        _add_disk_as_raw_container_to_target(drive, mock_target)
        assert isinstance(mock_method.call_args[0][0], RawContainer) is True
    mock.assert_called_with("/xdev/fake", "rb")

    # Does it emit a warning instead of raising an exception?
    mock.side_effect = IOError
    with (patch.object(TargetLogAdapter, "warning") as mock_method, patch("builtins.open", mock)):
        drive = "/xdev/fake"
        _add_disk_as_raw_container_to_target(drive, mock_target)
        assert mock_method.call_args[0][0] == "Unable to open drive: /xdev/fake, skipped"
        assert isinstance(mock_method.call_args[1]["exc_info"], OSError) is True
    mock.assert_called_with("/xdev/fake", "rb")


@pytest.mark.parametrize("drive_name,expected", testdata_linux_drive_regex)
def test_linux_drive_regex(drive_name, expected):
    assert (LINUX_DRIVE_REGEX.match(drive_name) is not None) == expected
