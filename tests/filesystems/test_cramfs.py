from __future__ import annotations

import gzip
from typing import TYPE_CHECKING

import pytest

from dissect.target.filesystems.cramfs import CramfsFilesystem, CramfsFilesystemEntry, c_cramfs
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator


def test_cramfs_detect() -> None:
    """Test that CramFS filesystems are correctly detected."""
    with gzip.open(absolute_path("_data/filesystems/cramfs/cramfs.bin.gz"), "rb") as fh:
        assert CramfsFilesystem.detect(fh)
        assert CramfsFilesystem(fh).cramfs


@pytest.fixture
def cramfs() -> Iterator[CramfsFilesystemEntry]:
    with gzip.open(absolute_path("_data/filesystems/cramfs/cramfs.bin.gz"), "rb") as fh:
        cramfs = CramfsFilesystem(fh)
        yield cramfs


@pytest.mark.parametrize(
    ("entry_path", "expected_blocks"),
    [
        ("/bin", 1),
        ("/home", 0),
        ("/bin/dvrbox", 6),
    ],
)
def test_cramfs_stat(cramfs: CramfsFilesystem, entry_path: str, expected_blocks: int) -> None:
    """Test consistency in ``stat()`` results."""
    cramfs_entry = cramfs.get(entry_path)
    inode = cramfs_entry.entry

    stat = cramfs_entry.stat()
    assert stat.st_mode == inode.mode
    assert stat.st_ino == inode.offset
    assert stat.st_dev == id(cramfs_entry.fs)
    assert stat.st_nlink == 1
    assert stat.st_uid == inode.uid
    assert stat.st_gid == inode.gid
    assert stat.st_size == inode.size
    assert stat.st_blksize == c_cramfs.CRAMFS_BLOCK_SIZE
    assert stat.st_blocks == expected_blocks


def test_cramfs_symlinks(cramfs: CramfsFilesystem) -> None:
    symlink = cramfs.get("/bin/macGuarder")
    target = cramfs.get("/bin/dvrbox")

    assert symlink.is_file()
    assert symlink.is_symlink()
    assert symlink.name == "macGuarder"
    assert symlink.readlink() == "./dvrbox"
    assert symlink.readlink_ext().name == target.name

    assert target.is_file()
    assert target.name == "dvrbox"


def test_cramfs_dir(cramfs: CramfsFilesystem) -> None:
    dir = cramfs.get("/etc/init.d")
    assert dir.is_dir()

    entries = list(dir.iterdir())
    assert len(entries) == 2
    assert sorted(entries) == sorted(["dnode", "rcS"])

    entries = [entry.name for entry in dir.scandir()]
    assert dir.is_dir()
    assert len(entries) == 2
    assert sorted(entries) == sorted(["dnode", "rcS"])
