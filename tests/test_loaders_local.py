from pathlib import Path
from unittest.mock import MagicMock, call, create_autospec, mock_open, patch

import pytest

from dissect.target import Target
from dissect.target.containers.raw import RawContainer
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.loaders.local import (
    LINUX_DEV_DIR,
    LINUX_DRIVE_REGEX,
    _add_disk_as_raw_container_to_target,
    _get_windows_drive_volumes,
    map_linux_drives,
)
from dissect.target.target import TargetLogAdapter


@patch("builtins.open", create=True)
@patch("ctypes.windll.kernel32.GetDriveTypeA", create=True, return_value=3)
@patch("ctypes.windll", create=True)
@patch("dissect.util.stream.BufferedStream", create=True)
@patch("dissect.target.loaders.local._read_drive_letters", create=True, return_value=[b"Z:"])
@patch("dissect.target.volume.Volume", create=True)
@patch("dissect.target.target.TargetLogAdapter", create=True)
@patch("dissect.target.loaders.local._windows_get_volume_disk_extents", create=True)
def test_local_loader_skip_emulated_drive(extents: MagicMock, log: MagicMock, *args) -> None:
    class Dummy:
        def __init__(self, data):
            self.__dict__ = data

    dummy = Dummy(
        {"NumberOfDiskExtents": 1, "Extents": [Dummy({"DiskNumber": "999", "StartingOffset": 0, "ExtentLength": 0})]}
    )
    extents.return_value = dummy
    for volume in _get_windows_drive_volumes(log):
        pass
    assert (
        call.debug(
            "Skipped drive %d from %s, not a physical drive (could be emulation or ram disk)", "999", "\\\\.\\z:"
        )
        in log.mock_calls
    )


def test__add_disk_as_raw_container_to_target(target_bare: Target) -> None:
    # Does it attempt to open the file and pass a raw container?
    mock = mock_open()
    drive = Path("/xdev/fake")

    with (
        patch("builtins.open", mock),
        patch.object(target_bare.disks, "add") as mock_method,
    ):
        _add_disk_as_raw_container_to_target(drive, target_bare)

        assert isinstance(mock_method.call_args[0][0], RawContainer) is True
        mock.assert_called_with(drive, "rb")


def test__add_disk_as_raw_container_to_target_skip_fail(target_bare: Target) -> None:
    # Does it emit a warning instead of raising an exception?
    mock = mock_open()
    mock.side_effect = IOError
    drive = Path("/xdev/fake")

    with (
        patch.object(TargetLogAdapter, "warning") as mock_method,
        patch("builtins.open", mock),
    ):
        _add_disk_as_raw_container_to_target(drive, target_bare)

        assert mock_method.call_args[0][0] == f"Unable to open drive: {str(drive)}, skipped"
        assert isinstance(mock_method.call_args[1]["exc_info"], OSError) is True
        mock.assert_called_with(drive, "rb")


def test_map_linux_drives(target_bare: Target, tmp_path: Path) -> None:
    mock_drive = LINUX_DEV_DIR.joinpath("sda")
    mock_dev_dir = create_autospec(Path)
    mock_dev_dir.iterdir.return_value = iter([mock_drive])

    with (
        patch("dissect.target.loaders.local.LINUX_DEV_DIR", mock_dev_dir),
        patch(
            "dissect.target.loaders.local._add_disk_as_raw_container_to_target",
            autospec=True,
        ) as mock_add_raw_disks,
        patch("dissect.target.loaders.local.VOLATILE_LINUX_PATHS", [tmp_path]),
        patch.object(target_bare.filesystems, "add", autospec=True) as mock_add_fs,
        patch.object(target_bare.fs, "mount", autospec=True) as mock_mount,
    ):
        map_linux_drives(target_bare)

        mock_add_raw_disks.assert_called_with(mock_drive, target_bare)

        mock_add_fs.assert_called()
        dir_fs = mock_add_fs.call_args[0][0]
        assert isinstance(dir_fs, DirectoryFilesystem)
        assert dir_fs.base_path == tmp_path

        mock_mount.assert_called_with(str(tmp_path), dir_fs)


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
def test_linux_drive_regex(drive_path: Path, expected: bool) -> None:
    assert (LINUX_DRIVE_REGEX.match(drive_path.name) is not None) == expected
