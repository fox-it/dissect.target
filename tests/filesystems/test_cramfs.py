from __future__ import annotations

import gzip
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest

from dissect.target.filesystems.cramfs import CramFSFilesystem, CramFSFilesystemEntry, c_cramfs
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.mark.parametrize(
    "filename",
    [
        "_data/filesystems/cramfs/cramfs.bin.gz",
    ],
)
def test_cramfs_detect(filename: str) -> None:
    """Test that CramFS filesystems are correctly detected."""
    with gzip.open(absolute_path(filename), "rb") as fh:
        assert CramFSFilesystem.detect(fh)
        assert CramFSFilesystem(fh).cramfs


@pytest.fixture
def cramfs() -> Iterator[CramFSFilesystemEntry]:
    with gzip.open(absolute_path("_data/filesystems/cramfs/cramfs.bin.gz"), "rb") as fh:
        cramfs = CramFSFilesystem(fh)
        yield cramfs


@pytest.fixture
def cramfs_file_entry(cramfs: CramFSFilesystem) -> Iterator[CramFSFilesystemEntry]:
    inode = Mock(
        inum=0,
        nlink=1,
        blocks=[0],
        is_dir=lambda: False,
        is_file=lambda: True,
        is_symlink=lambda: False,
    )

    return CramFSFilesystemEntry(cramfs, "/some_file", inode)


@pytest.mark.parametrize(
    ("entry_fixture", "expected_blocks"),
    [("cramfs_file_entry", 1)],
)
def test_cramfs_stat(entry_fixture: str, expected_blocks: int, request: pytest.FixtureRequest) -> None:
    """Test consistency in ``stat()`` results."""
    cramfs_entry: CramFSFilesystemEntry = request.getfixturevalue(entry_fixture)
    stat = cramfs_entry.stat()

    entry = cramfs_entry.entry
    assert stat.st_mode == entry.mode
    assert stat.st_ino == entry.inum
    assert stat.st_dev == id(cramfs_entry.fs)
    assert stat.st_nlink == entry.nlink
    assert stat.st_uid == entry.uid
    assert stat.st_gid == entry.gid
    assert stat.st_size == entry.size
    assert stat.st_blksize == c_cramfs.CRAMFS_BLOCK_SIZE
    assert stat.st_blocks == expected_blocks


def test_cramfs_symlinks(cramfs: CramFSFilesystem) -> None:
    symlink = cramfs.get("/bin/macGuarder")
    target = cramfs.get("/bin/dvrbox")

    assert symlink.is_file()
    assert symlink.is_symlink()
    assert symlink.name == "macGuarder"
    assert symlink.readlink() == "./dvrbox"
    assert symlink.readlink_ext().name == target.name

    assert target.is_file()
    assert target.name == "dvrbox"


def test_cramfs_dir(cramfs: CramFSFilesystem) -> None:
    dir = cramfs.get("/etc/init.d")
    assert dir.is_dir()

    entries = list(dir.iterdir())
    assert len(entries) == 2
    assert sorted(entries) == sorted(["dnode", "rcS"])

    entries = [entry.name for entry in dir.scandir()]
    assert dir.is_dir()
    assert len(entries) == 2
    assert sorted(entries) == sorted(["dnode", "rcS"])
