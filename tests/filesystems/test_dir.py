from __future__ import annotations

import os
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


def test_case_insensitive_lookup_lists_directory_once(tmp_path: pathlib.Path) -> None:
    """Looking up many entries of one directory should not list that directory for every lookup."""
    big_dir = tmp_path / "Big"
    big_dir.mkdir()
    for i in range(50):
        (big_dir / f"File{i}.txt").write_text(str(i))

    fs = DirectoryFilesystem(path=tmp_path, case_sensitive=False)
    original_iterdir = type(tmp_path).iterdir

    with patch.object(type(tmp_path), "iterdir", autospec=True, side_effect=original_iterdir) as mock_iterdir:
        for i in range(50):
            assert fs.get(f"/big/FILE{i}.TXT").open().read() == str(i).encode()

        # One listing for the root and one for the big directory, regardless of the number of lookups
        assert mock_iterdir.call_count == 2


def test_case_insensitive_lookup_sees_new_entries(tmp_path: pathlib.Path) -> None:
    """A cached listing must not hide entries that are added to the directory afterwards."""
    fs = DirectoryFilesystem(path=tmp_path, case_sensitive=False)
    (tmp_path / "first").write_text("1")
    assert fs.exists("/FIRST")
    assert not fs.exists("/Second")

    (tmp_path / "second").write_text("2")
    # Make sure the change is visible even on filesystems with a coarse mtime granularity
    stat = tmp_path.stat()
    os.utime(tmp_path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))

    assert fs.exists("/Second")


def test_case_insensitive_lookup_ambiguous(tmp_path: pathlib.Path) -> None:
    """Names that only differ in case are ambiguous and must not resolve."""
    (tmp_path / "Dup").write_text("a")
    if (tmp_path / "dup").exists():
        pytest.skip("Skip test as filesystem is not case sensitive (e.g NTFS)")
    (tmp_path / "dup").write_text("b")

    fs = DirectoryFilesystem(path=tmp_path, case_sensitive=False)
    assert not fs.exists("/DUP")
