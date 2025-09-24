from __future__ import annotations

from pathlib import Path
from typing import Callable
from unittest.mock import call, create_autospec, mock_open, patch

import pytest

from dissect.target.containers.raw import RawContainer
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.loaders.local import (
    LINUX_DEV_DIR,
    LINUX_DRIVE_REGEX,
    LocalLoader,
    _add_disk_as_raw_container_to_target,
    _get_windows_drive_volumes,
    map_linux_drives,
)
from dissect.target.target import Target, TargetLogAdapter


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target]) -> None:
    """Test that we correctly use ``LocalLoader`` when opening a ``Target``."""
    for path in ["local", "local?some=query"]:
        with patch("dissect.target.target.Target.apply"):
            target = opener(path)
            assert isinstance(target._loader, LocalLoader)
            assert target.path == Path("local")

            if "?" in path:
                assert target.path_query == {"some": "query"}


def test_skip_emulated_drive() -> None:
    """Test that we skip emulated drives on Windows."""

    class Dummy:
        def __init__(self, data: dict):
            self.__dict__ = data

    dummy = Dummy(
        {"NumberOfDiskExtents": 1, "Extents": [Dummy({"DiskNumber": "999", "StartingOffset": 0, "ExtentLength": 0})]}
    )

    with (
        patch("builtins.open", create=True),
        patch("ctypes.windll", create=True),
        patch("ctypes.windll.kernel32.GetDriveTypeA", create=True, return_value=3),
        patch("dissect.util.stream.BufferedStream", create=True),
        patch("dissect.target.loaders.local._read_drive_letters", create=True, return_value=[b"Z:"]),
        patch("dissect.target.volume.Volume", create=True),
        patch("dissect.target.target.TargetLogAdapter", create=True) as mock_log,
        patch("dissect.target.loaders.local._windows_get_volume_disk_extents", create=True) as mock_extents,
    ):
        mock_extents.return_value = dummy

        for _ in _get_windows_drive_volumes(mock_log):
            pass

        assert (
            call.debug(
                "Skipped drive %d from %s, not a physical drive (could be emulation or ram disk)", "999", "\\\\.\\z:"
            )
            in mock_log.mock_calls
        )


def test_add_disk_as_raw_container_to_target() -> None:
    """Test that we add a disk as a raw container to the target."""
    # Does it attempt to open the file and pass a raw container?
    mock = mock_open()
    drive = Path("/xdev/fake")
    t = Target()

    with (
        patch("pathlib.Path.open", mock),
        patch.object(t.disks, "add") as mock_method,
    ):
        _add_disk_as_raw_container_to_target(drive, t)

        assert isinstance(mock_method.call_args[0][0], RawContainer) is True
        mock.assert_called_with("rb")


def test_add_disk_as_raw_container_to_target_skip_fail() -> None:
    """Test that we skip adding a disk as a raw container if it fails to open."""
    # Does it emit a warning instead of raising an exception?
    mock = mock_open()
    mock.side_effect = IOError
    drive = Path("/xdev/fake")
    t = Target()

    with (
        patch.object(TargetLogAdapter, "warning") as mock_warning,
        patch.object(TargetLogAdapter, "debug") as mock_debug,
        patch("pathlib.Path.open", mock),
    ):
        _add_disk_as_raw_container_to_target(drive, t)

        assert mock_warning.call_args[0] == ("Unable to open drive: %s, skipped", drive)
        assert isinstance(mock_debug.call_args[1]["exc_info"], OSError) is True
        mock.assert_called_with("rb")


def test_map_linux_drives(tmp_path: Path) -> None:
    """Test that we correctly map Linux drives to the target."""
    mock_drive = LINUX_DEV_DIR.joinpath("sda")
    mock_dev_dir = create_autospec(Path)
    mock_dev_dir.iterdir.return_value = iter([mock_drive])

    t = Target()

    with (
        patch("dissect.target.loaders.local.LINUX_DEV_DIR", mock_dev_dir),
        patch(
            "dissect.target.loaders.local._add_disk_as_raw_container_to_target",
            autospec=True,
        ) as mock_add_raw_disks,
        patch("dissect.target.loaders.local.VOLATILE_LINUX_PATHS", [tmp_path]),
        patch.object(t.filesystems, "add", autospec=True) as mock_add_fs,
        patch.object(t.fs, "mount", autospec=True) as mock_mount,
    ):
        map_linux_drives(t)

        mock_add_raw_disks.assert_called_with(mock_drive, t)

        mock_add_fs.assert_called()
        dir_fs = mock_add_fs.call_args[0][0]
        assert isinstance(dir_fs, DirectoryFilesystem)
        assert dir_fs.base_path == tmp_path

        mock_mount.assert_called_with(str(tmp_path), dir_fs)


@pytest.mark.parametrize(
    ("drive_path", "expected"),
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
        (Path("/dev/vda"), True),  # Virtual hard disk
        (Path("/dev/vdb"), True),  # Virtual hard disk
        (Path("/dev/vda1"), False),  # Partition
        (Path("/dev/sr0"), False),  # Compact Disc
        (Path("/dev/scd0"), False),  # Compact Disc
        (Path("/dev/tty11"), False),  # Not a disk
        (Path("/dev/xsdaa"), False),  # Fake
        (Path("/dev/xhdaa"), False),  # Fake
    ],
)
def test_linux_drive_regex(drive_path: Path, expected: bool) -> None:
    """Test that we correctly match Linux drive paths."""
    assert (LINUX_DRIVE_REGEX.match(drive_path.name) is not None) == expected
