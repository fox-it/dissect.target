from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock

import pytest

from dissect.target.filesystem import FilesystemEntry, VirtualFile, VirtualFilesystem
from dissect.target.loaders.tar import TarLoader
from dissect.target.plugins.filesystem.walkfs import WalkFSPlugin, get_disk_serial
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
    print(results)
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


def test_get_disk_serial(mock_fs_entry: MagicMock) -> None:
    """Test get_disk_serial when a serial number is available."""
    # Mock the `serial` attribute on the `vs` object
    mock_fs_entry.fs.volume.vs = Mock(serial="A1B2C3D4")

    assert get_disk_serial(mock_fs_entry.fs) == "A1B2C3D4"


def test_get_disk_serial_no_serial(mock_fs_entry: MagicMock) -> None:
    """Test get_disk_serial when the `serial` attribute is missing."""
    # The default mock aparently does have the `serial` attribute on `vs`

    mock_fs_entry.fs.volume.disk.vs = Mock()
    if hasattr(mock_fs_entry.fs.volume.vs, "serial"):
        delattr(mock_fs_entry.fs.volume.vs, "serial")
    assert get_disk_serial(mock_fs_entry.fs) is None
