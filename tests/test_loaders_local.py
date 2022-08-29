import pytest
from pathlib import Path

from unittest.mock import patch, mock_open

from dissect.target.containers.raw import RawContainer
from dissect.target.loaders.local import _add_disk_as_raw_container_to_target, LINUX_DRIVE_REGEX
from dissect.target.target import TargetLogAdapter


def test_local_loader_drive_skipping(mock_target):
    mock = mock_open()
    # Does it attempt to open the file and pass a raw container?
    with (patch("builtins.open", mock), patch.object(mock_target.disks, "add") as mock_method):
        drive = Path("/xdev/fake")
        _add_disk_as_raw_container_to_target(drive, mock_target)
        assert isinstance(mock_method.call_args[0][0], RawContainer) is True
    mock.assert_called_with(Path("/xdev/fake"), "rb")

    # Does it emit a warning instead of raising an exception?
    mock.side_effect = IOError
    with (patch.object(TargetLogAdapter, "warning") as mock_method, patch("builtins.open", mock)):
        drive = Path("/xdev/fake")
        _add_disk_as_raw_container_to_target(drive, mock_target)
        assert mock_method.call_args[0][0] == "Unable to open drive: /xdev/fake, skipped"
        assert isinstance(mock_method.call_args[1]["exc_info"], OSError) is True
    mock.assert_called_with(Path("/xdev/fake"), "rb")


@pytest.mark.parametrize(
    "drive_path, expected",
    [
        (Path("/dev/fd0"), True),  # Floppy
        (Path("/dev/fd1"), True),  # Floppy
        (Path("/dev/fd2"), True),  # Floppy
        (Path("/dev/sda"), True),  # SCSI
        (Path("/dev/sdb"), True),  # SCSI
        (Path("/dev/sdc"), True),  # SCSI
        (Path("/dev/sda1"), False),  # Partition
        (Path("/dev/nvme0n1"), True),  # NVMe Disk
        (Path("/dev/nvme0n1p1"), False),  # Partition
        (Path("/dev/hda"), True),  # IDE-Controller
        (Path("/dev/hdb"), True),  # IDE-Controller
        (Path("/dev/hda1"), False),  # Partition
        (Path("/dev/sr0"), False),  # Compact Disc
        (Path("/dev/scd0"), False),  # Compact Disc
        (Path("/dev/tty11"), False),  # Not a disk
        (Path("/dev/xsdaa"), False),  # Fake
        (Path("/dev/xhdaa"), False),  # Fake
    ],
)
def test_linux_drive_regex(drive_path, expected):
    assert (LINUX_DRIVE_REGEX.match(drive_path.name) is not None) == expected
