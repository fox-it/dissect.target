from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock
from uuid import UUID

import pytest

from dissect.target.filesystem import FilesystemEntry, VirtualFile, VirtualFilesystem
from dissect.target.loaders.tar import TarLoader
from dissect.target.plugins.filesystem.walkfs import WalkFSPlugin, get_disk_serial, get_volume_uuid
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture

    from dissect.target.target import Target


def test_walkfs_plugin(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_entry("/path/to/some/file", VirtualFile(fs_unix, "file", None))
    fs_unix.map_file_entry("/path/to/some/other/file.ext", VirtualFile(fs_unix, "file.ext", None))
    fs_unix.map_file_entry("/root_file", VirtualFile(fs_unix, "root_file", None))
    fs_unix.map_file_entry("/other_root_file.ext", VirtualFile(fs_unix, "other_root_file.ext", None))
    fs_unix.map_file_entry("/.test/test.txt", VirtualFile(fs_unix, "test.txt", None))
    fs_unix.map_file_entry("/.test/.more.test.txt", VirtualFile(fs_unix, ".more.test.txt", None))

    target_unix.add_plugin(WalkFSPlugin)

    results = list(target_unix.walkfs())
    assert len(results) == 14
    assert sorted([r.path for r in results]) == [
        "/",
        "/.test",
        "/.test/.more.test.txt",
        "/.test/test.txt",
        "/etc",
        "/other_root_file.ext",
        "/path",
        "/path/to",
        "/path/to/some",
        "/path/to/some/file",
        "/path/to/some/other",
        "/path/to/some/other/file.ext",
        "/root_file",
        "/var",
    ]


@pytest.mark.benchmark
def test_benchmark_walkfs(target_bare: Target, benchmark: BenchmarkFixture) -> None:
    """Benchmark walkfs performance on a small tar archive with ~500 files."""

    loader = TarLoader(Path(absolute_path("_data/loaders/containerimage/alpine-docker.tar")))
    loader.map(target_bare)
    target_bare.apply()

    result = benchmark(lambda: next(WalkFSPlugin(target_bare).walkfs()))

    assert result.path == "/"


@pytest.fixture
def mock_fs_entry() -> MagicMock:
    """Fixture to create a mock FilesystemEntry object."""
    mock_entry = MagicMock(spec=FilesystemEntry)
    mock_fs = Mock()
    mock_volume = Mock()
    mock_disk = Mock()

    # Set up the mock object structure
    mock_entry.fs = mock_fs
    mock_fs.volume = mock_volume
    mock_volume.disk = mock_disk

    # Clear any attributes from previous tests
    mock_volume.guid = None
    mock_fs.__type__ = "generic"
    for attr in ("ntfs", "extfs", "fatfs", "exfat"):
        if hasattr(mock_fs, attr):
            setattr(mock_fs, attr, None)
    if hasattr(mock_disk.vs, "serial"):
        mock_disk.vs = None

    return mock_entry


def test_get_volume_uuid_ntfs(mock_fs_entry: MagicMock) -> None:
    """Test get_volume_uuid for an NTFS filesystem."""
    # Mock NTFS-specific attributes
    mock_fs_entry.fs.__type__ = "ntfs"
    mock_fs_entry.fs.ntfs = Mock(serial=123456789)

    expected_uuid = UUID(int=123456789)
    assert get_volume_uuid(mock_fs_entry) == expected_uuid


def test_get_volume_uuid_ext(mock_fs_entry: MagicMock) -> None:
    """Test get_volume_uuid for an EXT filesystem (ext2/3/4)."""
    # Mock EXT-specific attributes
    mock_fs_entry.fs.__type__ = "ext4"
    mock_fs_entry.fs.extfs = Mock(uuid="e0c3d987-a36c-4f9e-9b2f-90e633d7d7a1")

    expected_uuid = "e0c3d987-a36c-4f9e-9b2f-90e633d7d7a1"
    assert get_volume_uuid(mock_fs_entry) == expected_uuid


def test_get_volume_uuid_fat(mock_fs_entry: MagicMock) -> None:
    """Test get_volume_uuid for a FAT filesystem."""
    # Mock FAT-specific attributes
    mock_fs_entry.fs.__type__ = "fat"
    mock_fs_entry.fs.fatfs = Mock(volume_id="1a2b3c4d")

    expected_uuid = UUID(int=0x1A2B3C4D)
    assert get_volume_uuid(mock_fs_entry) == expected_uuid


def test_get_volume_uuid_exfat(mock_fs_entry: MagicMock) -> None:
    """Test get_volume_uuid for an ExFAT filesystem."""
    # Mock ExFAT-specific attributes
    mock_fs_entry.fs.__type__ = "exfat"
    mock_fs_entry.fs.exfat = Mock(vbr=Mock(volume_serial=987654321))

    expected_uuid = UUID(int=987654321)
    assert get_volume_uuid(mock_fs_entry) == expected_uuid


def test_get_volume_uuid_guid(mock_fs_entry: MagicMock) -> None:
    """Test get_volume_uuid when `volume.guid` exists (higher priority)."""
    # Mock a GUID that should be returned first
    mock_fs_entry.fs.volume.guid = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"

    expected_uuid = UUID(bytes_le=mock_fs_entry.fs.volume.guid)
    assert get_volume_uuid(mock_fs_entry) == expected_uuid


def test_get_volume_uuid_no_match(mock_fs_entry: MagicMock) -> None:
    """Test get_volume_uuid when no valid UUID is found."""
    # The default mock has no specific filesystem type
    mock_fs_entry.fs.__type__ = "unsupported_fs"

    assert get_volume_uuid(mock_fs_entry) is None


def test_get_disk_serial(mock_fs_entry: MagicMock) -> None:
    """Test get_disk_serial when a serial number is available."""
    # Mock the `serial` attribute on the `vs` object
    mock_fs_entry.fs.volume.disk.vs = Mock(serial="A1B2C3D4")

    assert get_disk_serial(mock_fs_entry) == "A1B2C3D4"


def test_get_disk_serial_no_serial(mock_fs_entry: MagicMock) -> None:
    """Test get_disk_serial when the `serial` attribute is missing."""
    # The default mock aparently does have the `serial` attribute on `vs`
    mock_fs_entry.fs.volume.disk.vs = Mock()
    if hasattr(mock_fs_entry.fs.volume.disk.vs, "serial"):
        delattr(mock_fs_entry.fs.volume.disk.vs, "serial")
    assert get_disk_serial(mock_fs_entry) is None
