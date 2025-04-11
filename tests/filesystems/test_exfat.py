from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.target.exceptions import FileNotFoundError, NotADirectoryError
from dissect.target.filesystems.exfat import ExfatFilesystem, ExfatFilesystemEntry

if TYPE_CHECKING:
    from collections.abc import Iterator


def mock_file(name: str, is_dir: bool = False) -> Mock:
    file = Mock(name=name)

    file.metadata = Mock()
    file.metadata.attributes = Mock()
    file.metadata.attributes.directory = is_dir

    file.stream = Mock()
    file.stream.data_length = 0

    return file


MOCK_EXFAT_FILE_TREE = {
    "/": (
        mock_file("Mock_", is_dir=True),
        {
            "some_path": (
                mock_file("Mock_some_path", is_dir=True),
                {
                    "some_file": (
                        mock_file("Mock_some_path_some_file"),
                        None,
                    ),
                    "other_file": (
                        mock_file("Mock_some_path_other_file"),
                        None,
                    ),
                },
            ),
            "other_file": (
                mock_file("Mock_other_file"),
                None,
            ),
        },
    ),
}


@pytest.fixture
def exfat_fs() -> Iterator[ExfatFilesystem]:
    with patch("dissect.fat.exfat.ExFAT"):
        exfat_fs = ExfatFilesystem(Mock())
        exfat_fs.exfat.files = MOCK_EXFAT_FILE_TREE

        yield exfat_fs


@pytest.fixture
def other_file(exfat_fs: ExfatFilesystem) -> ExfatFilesystemEntry:
    return ExfatFilesystemEntry(exfat_fs, "/other_file", MOCK_EXFAT_FILE_TREE["/"][1]["other_file"])


@pytest.fixture
def some_path(exfat_fs: ExfatFilesystem) -> ExfatFilesystemEntry:
    return ExfatFilesystemEntry(exfat_fs, "/some_path", MOCK_EXFAT_FILE_TREE["/"][1]["some_path"])


def test_filesystem_get(exfat_fs: ExfatFilesystem) -> None:
    path = "/some_path/SOME_FILE"
    some_file = exfat_fs.get(path)

    assert isinstance(some_file, ExfatFilesystemEntry)
    assert some_file.path == path
    assert some_file.entry[0]._mock_name == "Mock_some_path_some_file"


def test_filesystem__get_entry(exfat_fs: ExfatFilesystem) -> None:
    root = exfat_fs._get_entry("/")
    assert root[0]._mock_name == "Mock_"
    assert isinstance(root[1], dict)

    some_path = exfat_fs._get_entry("/some_path")

    assert some_path[0]._mock_name == "Mock_some_path"
    assert exfat_fs._get_entry("/SoMe_PaTh") == some_path

    other_file = exfat_fs._get_entry("/some_path/OTHER_FILE")

    assert other_file[0]._mock_name == "Mock_some_path_other_file"
    assert other_file[1] is None
    assert exfat_fs._get_entry("OTHER_FILE", root=some_path) == other_file


def test_filesystem__get_entry_not_a_directory_error(exfat_fs: ExfatFilesystem) -> None:
    with pytest.raises(NotADirectoryError):
        exfat_fs._get_entry("/other_file/non-exisiting_file")


def test_filesystem__get_entry_file_not_found_error(exfat_fs: ExfatFilesystem) -> None:
    with pytest.raises(FileNotFoundError):
        exfat_fs._get_entry("/non-exisiting_file")


def test_filesystem_entry_get(exfat_fs: ExfatFilesystem, some_path: ExfatFilesystemEntry) -> None:
    some_file = some_path.get("some_file")

    assert some_file.path == "/some_path/some_file"
    assert some_file.entry[0]._mock_name == "Mock_some_path_some_file"


def test_filesystem_entry__iterdir(exfat_fs: ExfatFilesystem, some_path: ExfatFilesystemEntry) -> None:
    file_names = []
    file_entries = []

    for entry_name, entry_file_tree in some_path._iterdir():
        file_names.append(entry_name)
        file_entries.append(entry_file_tree[0]._mock_name)

    assert len(file_names) == 2
    assert "some_file" in file_names
    assert "other_file" in file_names
    assert "Mock_some_path_some_file" in file_entries
    assert "Mock_some_path_other_file" in file_entries


def test_filesystem_entry__iterdir_raises(
    exfat_fs: ExfatFilesystem,
    other_file: ExfatFilesystemEntry,
) -> None:
    with pytest.raises(NotADirectoryError):
        list(other_file._iterdir())


def test_filesystem_entry_iterdir(
    exfat_fs: ExfatFilesystem,
    some_path: ExfatFilesystemEntry,
) -> None:
    file_names = list(some_path.iterdir())

    assert len(file_names) == 2
    assert "some_file" in file_names
    assert "other_file" in file_names


def test_filesystem_entry_iterdir_raises(
    exfat_fs: ExfatFilesystem,
    other_file: ExfatFilesystemEntry,
) -> None:
    with pytest.raises(NotADirectoryError):
        list(other_file.iterdir())


def test_filesystem_entry_scandir(
    exfat_fs: ExfatFilesystem,
    some_path: ExfatFilesystemEntry,
) -> None:
    file_names = [entry.name for entry in some_path.scandir()]

    assert len(file_names) == 2
    assert "some_file" in file_names
    assert "other_file" in file_names


def test_filesystem_entry_scandir_raises(
    exfat_fs: ExfatFilesystem,
    other_file: ExfatFilesystemEntry,
) -> None:
    with pytest.raises(NotADirectoryError):
        list(other_file.scandir())


def test_filesystem_entry_is_symlink(
    exfat_fs: ExfatFilesystem,
    other_file: ExfatFilesystemEntry,
    some_path: ExfatFilesystemEntry,
) -> None:
    assert not other_file.is_symlink()
    assert not some_path.is_symlink()


def test_filesystem_entry_is_dir(
    exfat_fs: ExfatFilesystem,
    other_file: ExfatFilesystemEntry,
    some_path: ExfatFilesystemEntry,
) -> None:
    assert not other_file.is_dir()
    assert some_path.is_dir()
    assert some_path.is_dir(follow_symlinks=False)


def test_filesystem_entry_is_file(
    exfat_fs: ExfatFilesystem,
    other_file: ExfatFilesystemEntry,
    some_path: ExfatFilesystemEntry,
) -> None:
    assert other_file.is_file()
    assert other_file.is_file(follow_symlinks=False)
    assert not some_path.is_file()
