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
    return DirectoryFilesystemEntry(Mock(sep="/"), "/some/path", Mock())


def test_entry_attr(dirfs_entry: DirectoryFilesystemEntry) -> None:
    with patch("dissect.target.helpers.fsutil.fs_attrs", autospec=True) as fs_attrs:
        dirfs_entry.attr()
        fs_attrs.assert_called_with(dirfs_entry.entry, follow_symlinks=True)


def test_entry_lattr(dirfs_entry: DirectoryFilesystemEntry) -> None:
    with patch("dissect.target.helpers.fsutil.fs_attrs", autospec=True) as fs_attrs:
        dirfs_entry.lattr()
        fs_attrs.assert_called_with(dirfs_entry.entry, follow_symlinks=False)


def test_multiple_nested_path_resolution(tmp_path: pathlib.Path) -> None:
    """Test some basic I/O operations."""
    nested_dir = tmp_path / "level1" / "level2" / "level3" / "level4"
    nested_dir.mkdir(parents=True)
    (nested_dir / "file5").write_text("file5 content")
    (tmp_path / "level1" / "level2" / "level3" / "file4").write_text("file4_content")
    fs = DirectoryFilesystem(path=tmp_path)
    assert not fs.exists("/level1/level2/level3/level4/level5")
    assert fs.exists("/level1/level2/level3/level4/file5")
    assert fs.exists("/level1/level2/level3/file4")

    dirents = {entry.name: entry for entry in fs.get("/level1/level2/level3").scandir()}
    assert len(dirents) == 2
    assert dirents["level4"].is_dir()

    fh_4 = dirents["file4"].get().open()
    assert fh_4.read() == b"file4_content"
    fh_4.close()

    fh_5 = fs.get("/level1/level2/level3/level4/file5").open()
    assert fh_5.read() == b"file5 content"
    fh_5.close()


def test_case_sensitivity(tmp_path: pathlib.Path) -> None:
    test_dir = tmp_path / "LeVel1"
    test_dir.mkdir(parents=True)
    if (tmp_path / "level1").exists():
        pytest.skip("Skip test as filesystem is not case sensitive (e.g NTFS)")
    (test_dir / "test_filE").write_text("test_content")
    fs_sensitive = DirectoryFilesystem(path=tmp_path)  # default to case sensitive
    fs_insensitive = DirectoryFilesystem(path=tmp_path, case_sensitive=False)
    assert not fs_sensitive.exists("/level1")
    assert fs_insensitive.exists("/level1")

    dirents_sensitive = {entry.name: entry for entry in fs_sensitive.get("/").scandir()}
    assert len(dirents_sensitive) == 1
    assert dirents_sensitive["LeVel1"].is_dir()

    assert fs_insensitive.get("level1").entry == fs_insensitive.get("LeVel1").entry
    fh = fs_insensitive.get("level1/test_file").open()
    assert fh.read() == b"test_content"
    fh.close()
