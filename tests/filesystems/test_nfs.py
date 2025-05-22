from __future__ import annotations

import stat
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from dissect.target.filesystems.nfs import NfsFilesystem, NfsFilesystemEntry, NfsStream
from dissect.target.helpers.nfs.nfs3 import (
    EntryPlus,
    FileAttributes,
    FileHandle,
    FileType,
    NfsTime,
    SpecData,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def mock_nfs_client() -> Iterator[MagicMock]:
    with patch("dissect.target.helpers.nfs.client.nfs.Client", autospec=True) as mock_client:
        yield mock_client


@pytest.fixture
def nfs_filesystem(mock_nfs_client: MagicMock) -> NfsFilesystem:
    client_factory = MagicMock(return_value=mock_nfs_client)
    root_handle = FileHandle(opaque=b"root_handle")
    return NfsFilesystem(client_factory, root_handle)


@pytest.fixture
def nfs_filesystem_entry(nfs_filesystem: NfsFilesystem) -> NfsFilesystemEntry:
    file_handle = FileHandle(opaque=b"file_handle")
    attributes = FileAttributes(
        type=FileType.REG,
        mode=0o644,
        nlink=1,
        uid=1000,
        gid=1000,
        size=1024,
        used=1024,
        rdev=SpecData(8, 9),
        fsid=0,
        fileid=0,
        atime=NfsTime(1, 2),
        mtime=NfsTime(3, 4),
        ctime=NfsTime(5, 6),
    )
    return NfsFilesystemEntry(nfs_filesystem, "/file", file_handle, attributes)


def test_get_root(nfs_filesystem: NfsFilesystem) -> None:
    entry = nfs_filesystem.get("/")
    assert isinstance(entry, NfsFilesystemEntry)
    assert entry.path == "/"
    assert entry.entry.opaque == b"root_handle"


def test_get_subdirectory(nfs_filesystem: NfsFilesystem, mock_nfs_client: MagicMock) -> None:
    mock_nfs_client.lookup.return_value = MagicMock(
        object=FileHandle(opaque=b"subdir_handle"), obj_attributes=MagicMock()
    )
    entry = nfs_filesystem.get("/subdir")
    mock_nfs_client.lookup.assert_called_with("subdir", FileHandle(opaque=b"root_handle"))
    assert isinstance(entry, NfsFilesystemEntry)
    assert entry.path == "subdir"
    assert entry.entry.opaque == b"subdir_handle"


def test_get_from_entry(mock_nfs_client: MagicMock, nfs_filesystem_entry: NfsFilesystemEntry) -> None:
    nfs_filesystem_entry._attributes.type = FileType.DIR
    mock_nfs_client.lookup.return_value = MagicMock(
        object=FileHandle(opaque=b"subdir_handle"), obj_attributes=MagicMock()
    )
    entry = nfs_filesystem_entry.get("subdir")
    mock_nfs_client.lookup.assert_called_with("subdir", nfs_filesystem_entry.entry)
    assert isinstance(entry, NfsFilesystemEntry)
    assert entry.path == "subdir"
    assert entry.entry.opaque == b"subdir_handle"


def test_is_file(nfs_filesystem_entry: NfsFilesystemEntry) -> None:
    nfs_filesystem_entry._attributes.type = FileType.REG
    assert nfs_filesystem_entry.is_file()


def test_is_dir(nfs_filesystem_entry: NfsFilesystemEntry) -> None:
    nfs_filesystem_entry._attributes.type = FileType.DIR
    assert nfs_filesystem_entry.is_dir()


def test_is_symlink(nfs_filesystem_entry: NfsFilesystemEntry) -> None:
    nfs_filesystem_entry._attributes.type = FileType.LNK
    assert nfs_filesystem_entry.is_symlink()


def test_readlink(nfs_filesystem_entry: NfsFilesystemEntry, mock_nfs_client: MagicMock) -> None:
    mock_nfs_client.readlink.return_value = "/target"
    target = nfs_filesystem_entry.readlink()
    mock_nfs_client.readlink.assert_called_with(FileHandle(opaque=b"file_handle"))
    assert target == "/target"


def test_iterdir(nfs_filesystem_entry: NfsFilesystemEntry, mock_nfs_client: MagicMock) -> None:
    nfs_filesystem_entry._attributes.type = FileType.DIR
    mock_nfs_client.readdir.return_value = MagicMock(
        entries=[
            EntryPlus(
                fileid=1,
                cookie=1,
                name="file1",
                handle=FileHandle(opaque=b"file1_handle"),
                attributes=nfs_filesystem_entry._attributes,
            ),
            EntryPlus(
                fileid=2,
                cookie=2,
                name="file2",
                handle=FileHandle(opaque=b"file2_handle"),
                attributes=nfs_filesystem_entry._attributes,
            ),
        ]
    )
    entries = list(nfs_filesystem_entry.iterdir())
    mock_nfs_client.readdir.assert_called_with(FileHandle(opaque=b"file_handle"))
    assert entries == ["file1", "file2"]


def test_stat(nfs_filesystem_entry: NfsFilesystemEntry) -> None:
    stat_result = nfs_filesystem_entry.stat()
    assert stat_result.st_mode == nfs_filesystem_entry._attributes.mode | stat.S_IFREG
    assert stat_result.st_uid == nfs_filesystem_entry._attributes.uid
    assert stat_result.st_gid == nfs_filesystem_entry._attributes.gid
    assert stat_result.st_size == nfs_filesystem_entry._attributes.size
    assert stat_result.st_atime == nfs_filesystem_entry._attributes.atime.seconds
    assert stat_result.st_mtime == nfs_filesystem_entry._attributes.mtime.seconds
    assert stat_result.st_ctime == nfs_filesystem_entry._attributes.ctime.seconds
    assert stat_result.st_atime_ns == nfs_filesystem_entry._attributes.atime.nseconds
    assert stat_result.st_mtime_ns == nfs_filesystem_entry._attributes.mtime.nseconds
    assert stat_result.st_ctime_ns == nfs_filesystem_entry._attributes.ctime.nseconds


def test_open(nfs_filesystem_entry: NfsFilesystemEntry, mock_nfs_client: MagicMock) -> None:
    stream = nfs_filesystem_entry.open()
    assert isinstance(stream, NfsStream)
    assert stream._client == mock_nfs_client
    assert stream._file_handle.opaque == nfs_filesystem_entry.entry.opaque
    assert stream.size == nfs_filesystem_entry._attributes.size


def test_stream_read(nfs_filesystem_entry: NfsFilesystemEntry, mock_nfs_client: MagicMock) -> None:
    mock_nfs_client.readfile.return_value = iter([b"hello", b" ", b"world"])
    stream = nfs_filesystem_entry.open()
    data = stream.read()
    assert data == b"hello world"
    mock_nfs_client.readfile.assert_called_with(FileHandle(opaque=b"file_handle"), 0, 1024 * 1024)
