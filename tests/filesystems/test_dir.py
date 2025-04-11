from __future__ import annotations

import pathlib
import tempfile
from unittest.mock import Mock, patch

import pytest

from dissect.target.filesystems.dir import DirectoryFilesystem, DirectoryFilesystemEntry


def test_symlink_to_file(tmp_path: pathlib.Path) -> None:
    with tempfile.NamedTemporaryFile(dir=tmp_path, delete=False) as tf:
        tf.write(b"dummy")
        tf.close()

        tmpfile_path = pathlib.Path(tf.name)
        symlink_path = tmp_path.joinpath("symlink")
        symlink_path.symlink_to(f"/{tmpfile_path.name}")

        fs = DirectoryFilesystem(path=tmp_path)
        symlink_entry = fs.get("symlink")

        assert symlink_entry.is_symlink()
        assert symlink_entry.is_file()
        assert not symlink_entry.is_file(follow_symlinks=False)
        assert not symlink_entry.is_dir()
        assert symlink_entry.exists()
        assert symlink_entry.stat(follow_symlinks=False) == symlink_entry.lstat()

        assert symlink_entry.readlink() == f"/{tmpfile_path.name}"
        assert symlink_entry.readlink_ext().entry == fs.get(tmpfile_path.name).entry

        assert symlink_entry.open().read() == fs.get(tmpfile_path.name).open().read() == b"dummy"

        assert list(symlink_entry.lstat()) == list(symlink_path.lstat())
        assert list(symlink_entry.stat()) == list(tmpfile_path.lstat())


def test_symlink_to_dir(tmp_path: pathlib.Path) -> None:
    nested_path = tmp_path.joinpath("nested")
    nested_path.mkdir()
    nested_path.joinpath("file1").touch()
    nested_path.joinpath("file2").touch()

    symlink_path = tmp_path.joinpath("symlink")
    symlink_path.symlink_to("/nested")

    fs = DirectoryFilesystem(path=tmp_path)
    symlink_entry = fs.get("symlink")

    assert symlink_entry.is_symlink()
    assert not symlink_entry.is_file()
    assert symlink_entry.is_dir()
    assert not symlink_entry.is_dir(follow_symlinks=False)
    assert symlink_entry.exists()
    assert symlink_entry.stat(follow_symlinks=False) == symlink_entry.lstat()

    assert symlink_entry.readlink() == "/nested"
    assert symlink_entry.readlink_ext().entry == fs.get("/nested").entry

    assert sorted(symlink_entry.iterdir()) == ["file1", "file2"]
    assert sorted([e.entry for e in symlink_entry.scandir()], key=lambda e: e.name) == [
        fs.get("/nested/file1").entry,
        fs.get("/nested/file2").entry,
    ]


@pytest.fixture
def dirfs_entry() -> DirectoryFilesystemEntry:
    return DirectoryFilesystemEntry(Mock(), "/some/path", Mock())


def test_entry_attr(dirfs_entry: DirectoryFilesystemEntry) -> None:
    with patch("dissect.target.helpers.fsutil.fs_attrs", autospec=True) as fs_attrs:
        dirfs_entry.attr()
        fs_attrs.assert_called_with(dirfs_entry.entry, follow_symlinks=True)


def test_entry_lattr(dirfs_entry: DirectoryFilesystemEntry) -> None:
    with patch("dissect.target.helpers.fsutil.fs_attrs", autospec=True) as fs_attrs:
        dirfs_entry.lattr()
        fs_attrs.assert_called_with(dirfs_entry.entry, follow_symlinks=False)
