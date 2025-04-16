from __future__ import annotations

import bz2
import gzip
import io
import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable
from unittest.mock import Mock, patch

import pytest

from dissect.target.exceptions import (
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
    SymlinkRecursionError,
)
from dissect.target.filesystem import VirtualFile, VirtualFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.filesystems.ntfs import NtfsFilesystemEntry
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("path", "alt_separator", "result"),
    [
        ("/some/dir/some/file", "", "/some/dir/some/file"),
        ("/some/dir/some/file", "\\", "/some/dir/some/file"),
        ("\\some\\dir\\some\\file", "\\", "/some/dir/some/file"),
        ("/some///long\\\\dir/so\\//me\\file", "", "/some/long\\\\dir/so\\/me\\file"),
        ("/some///long\\\\dir/so\\//me\\file", "\\", "/some/long/dir/so/me/file"),
    ],
)
def test_normalize(path: str, alt_separator: str, result: str) -> None:
    assert fsutil.normalize(path, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("args", "alt_separator", "result"),
    [
        (("/some/dir", "some/file"), "", "/some/dir/some/file"),
        (("/some/dir", "some/file"), "\\", "/some/dir/some/file"),
        (("\\some\\dir", "some\\file"), "\\", "/some/dir/some/file"),
        (("/some///long\\\\dir", "so\\//me\\file"), "", "/some/long\\\\dir/so\\/me\\file"),
        (("/some///long\\\\dir", "so\\//me\\file"), "\\", "/some/long/dir/so/me/file"),
    ],
)
def test_join(args: str, alt_separator: str, result: str) -> None:
    assert fsutil.join(*args, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path", "alt_separator", "result"),
    [
        ("/some/dir/some/file", "", "/some/dir/some"),
        ("/some/dir/some/file", "\\", "/some/dir/some"),
        ("\\some\\dir\\some\\file", "\\", "/some/dir/some"),
        ("/some///long\\\\dir/so\\//me\\file", "", "/some/long\\\\dir/so\\"),
        ("/some///long\\\\dir/so\\//me\\file", "\\", "/some/long/dir/so/me"),
    ],
)
def test_dirname(path: str, alt_separator: str, result: str) -> None:
    assert fsutil.dirname(path, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path", "alt_separator", "result"),
    [
        ("/some/dir/some/file", "", "file"),
        ("/some/dir/some/file", "\\", "file"),
        ("\\some\\dir\\some\\file", "\\", "file"),
        ("/some///long\\\\dir/so\\//me\\file", "", "me\\file"),
        ("/some///long\\\\dir/so\\//me\\file", "\\", "file"),
    ],
)
def test_basename(path: str, alt_separator: str, result: str) -> None:
    assert fsutil.basename(path, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path", "alt_separator", "result"),
    [
        ("/some/dir/some/file", "", ("/some/dir/some", "file")),
        ("/some/dir/some/file", "\\", ("/some/dir/some", "file")),
        ("\\some\\dir\\some\\file", "\\", ("/some/dir/some", "file")),
        ("/some/dir/some/", "", ("/some/dir/some", "")),
        ("/some/dir/some\\", "", ("/some/dir", "some\\")),
        ("/some/dir/some/", "\\", ("/some/dir/some", "")),
        ("\\some\\dir\\some\\", "\\", ("/some/dir/some", "")),
        ("/some///long\\\\dir/so\\//me\\file", "", ("/some/long\\\\dir/so\\", "me\\file")),
        ("/some///long\\\\dir/so\\//me\\file", "\\", ("/some/long/dir/so/me", "file")),
    ],
)
def test_split(path: str, alt_separator: str, result: str) -> None:
    assert fsutil.split(path, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path", "alt_separator", "result"),
    [
        ("/some/dir", "", True),
        ("some/dir", "", False),
        ("\\some/dir", "", False),
        ("/some/dir", "\\", True),
        ("some/dir", "\\", False),
        ("\\some/dir", "\\", True),
    ],
)
def test_isabs(path: str, alt_separator: str, result: str) -> None:
    assert fsutil.isabs(path, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path", "alt_separator", "result"),
    [
        ("/some/dir/../some/file", "", "/some/some/file"),
        ("/some/dir/../some/file", "\\", "/some/some/file"),
        ("\\some\\dir\\..\\some\\file", "\\", "/some/some/file"),
        ("/some///long\\..\\dir/so\\.//me\\file", "", "/some/long\\..\\dir/so\\./me\\file"),
        ("/some///long\\..\\dir/so\\.//me\\file", "\\", "/some/dir/so/me/file"),
    ],
)
def test_normpath(path: str, alt_separator: str, result: str) -> None:
    assert fsutil.normpath(path, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path", "cwd", "alt_separator", "result"),
    [
        ("/some/dir", "", "", "/some/dir"),
        ("some/dir", "", "", "/some/dir"),
        ("\\some/dir", "", "", "/\\some/dir"),
        ("/some/dir", "", "\\", "/some/dir"),
        ("some/dir", "", "\\", "/some/dir"),
        ("\\some\\dir", "", "\\", "/some/dir"),
        ("some\\dir", "", "\\", "/some/dir"),
        ("/some/dir", "/my/cwd/", "", "/some/dir"),
        ("\\some\\dir", "\\my\\cwd\\", "\\", "/some/dir"),
        ("some/dir", "/my/cwd/", "", "/my/cwd/some/dir"),
        ("some\\dir", "/my/cwd/", "\\", "/my/cwd/some/dir"),
        ("some/dir", "/my\\cwd/", "", "/my\\cwd/some/dir"),
        ("some\\dir", "/my\\cwd/", "\\", "/my/cwd/some/dir"),
    ],
)
def test_abspath(path: str, cwd: str, alt_separator: str, result: str) -> None:
    assert fsutil.abspath(path, cwd=cwd, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path", "start", "alt_separator", "result"),
    [
        ("/some/dir/some/file", "/some/dir", "", "some/file"),
        ("/some/dir/some/file", "/some/dir", "\\", "some/file"),
        ("\\some\\dir\\some\\file", "\\some\\dir", "\\", "some/file"),
        ("/some///long\\\\dir/so\\//me\\file", "/some/long/dir", "", "../../long\\\\dir/so\\/me\\file"),
        ("/some///long\\\\dir/so\\//me\\file", "/some/long\\\\dir", "", "so\\/me\\file"),
        ("/some///long\\\\dir/so\\//me\\file", "/some/long/dir", "\\", "so/me/file"),
        ("/some///long\\\\dir/so\\//me\\file", "/some/long\\\\dir", "\\", "so/me/file"),
    ],
)
def test_relpath(path: str, start: str, alt_separator: str, result: str) -> None:
    assert fsutil.relpath(path, start, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("paths", "alt_separator", "result"),
    [
        (["/some/dir/some/file", "/some/dir/some/other"], "", "/some/dir/some"),
        (["/some/dir/some/file", "/some/dir/some/other"], "\\", "/some/dir/some"),
        (["\\some\\dir\\some\\file", "\\some\\dir\\some\\other"], "\\", "/some/dir/some"),
        (["/some/dir/some/file", "/some/dir/other"], "", "/some/dir"),
        (["/some/dir/some/file", "/some/other"], "", "/some"),
        (["/some/dir/some/file", "/some/other"], "\\", "/some"),
    ],
)
def test_commonpath(paths: list[str], alt_separator: str, result: str) -> None:
    assert fsutil.commonpath(paths, alt_separator=alt_separator) == result


def test_isreserved() -> None:
    assert not fsutil.isreserved("CON")
    assert not fsutil.isreserved("foo")


def test_generate_addr() -> None:
    slash_path = "/some/dir/some/file"
    slash_vfs = VirtualFilesystem(alt_separator="")
    slash_target_path = fsutil.TargetPath(slash_vfs, slash_path)

    backslash_path = "\\some\\dir\\some\\file"
    backslash_vfs = VirtualFilesystem(alt_separator="\\")
    backslash_target_path = fsutil.TargetPath(backslash_vfs, backslash_path)

    assert (
        fsutil.generate_addr(slash_path, "")
        == fsutil.generate_addr(slash_path, "\\")
        == fsutil.generate_addr(backslash_path, "\\")
        == fsutil.generate_addr(slash_target_path, "")
        == fsutil.generate_addr(backslash_target_path, "")
        == fsutil.generate_addr(slash_target_path, "\\")
        == fsutil.generate_addr(backslash_target_path, "\\")
    )

    assert fsutil.generate_addr(slash_path, "") != fsutil.generate_addr(backslash_path, "")


def test_stat_result() -> None:
    with pytest.raises(TypeError):
        fsutil.stat_result([0])

    with pytest.raises(TypeError):
        fsutil.stat_result(list(range(100)))

    # ["st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "_st_atime", "_st_mtime", "_st_ctime"]
    values = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

    st = fsutil.stat_result(values)
    assert st[0] == st.st_mode == 0
    assert st[9] == 9
    assert st.st_ctime == 9.0
    assert st.st_ctime_ns == 9000000000
    assert st.st_blksize is None
    assert list(st) == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

    # [..., "st_atime", "st_mtime", "st_ctime", "st_atime_ns", "st_mtime_ns", "st_ctime_ns"]
    values += [10, 11, 12, 13, 14, 15]

    st = fsutil.stat_result(values)
    assert st[0] == st.st_mode == 0
    assert st[9] == 9
    assert st.st_ctime == 12.0
    assert st.st_ctime_ns == 15
    assert st.st_blksize is None
    assert list(st) == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

    my_stat = Path(__file__).stat()
    st = fsutil.stat_result.copy(my_stat)
    assert st == my_stat


@pytest.fixture
def path_fs() -> VirtualFilesystem:
    vfs = VirtualFilesystem()

    vfs.makedirs("/some/dir")
    vfs.makedirs("/some/dir/nested")
    vfs.symlink("/some/dir/file.txt", "/some/symlink.txt")
    vfs.symlink("nonexistent", "/some/dir/link.txt")
    vfs.symlink("/some/dir/nested", "/some/dirlink")
    vfs.map_file_fh("/some/file.txt", io.BytesIO(b"content"))
    vfs.map_file_fh("/some/dir/file.txt", io.BytesIO(b""))
    vfs.map_file_fh("/some/dir/nested/file.txt", io.BytesIO(b""))

    return vfs


def test_target_path_drive(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/file.txt").drive == ""


def test_target_path_root(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/file.txt").root == "/"


def test_target_path_anchor(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/file.txt").anchor == "/"


def test_target_path_parent(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/dir/file.txt").parent == path_fs.path("/some/dir")


def test_target_path_parents(path_fs: VirtualFilesystem) -> None:
    path = path_fs.path("/some/dir/file.txt")
    parents = list(path.parents)
    assert parents == [path_fs.path("/some/dir"), path_fs.path("/some"), path_fs.path("/")]
    assert [p.exists() for p in parents]
    assert all(p._fs == path_fs for p in parents)
    assert path.parents[1] == path.parents[-2] == path_fs.path("/some")


def test_target_path_name(path_fs: VirtualFilesystem) -> None:
    path = path_fs.path("/some/file.txt")
    assert path.name == "file.txt"


def test_target_path_suffix(path_fs: VirtualFilesystem) -> None:
    path = path_fs.path("/some/file.txt")
    assert path.suffix == ".txt"


def test_target_path_suffixes(path_fs: VirtualFilesystem) -> None:
    path = path_fs.path("/some/file.tar.gz")
    assert path.suffixes == [".tar", ".gz"]


def test_target_path_stem(path_fs: VirtualFilesystem) -> None:
    path = path_fs.path("/some/file.txt")
    assert path.stem == "file"


def test_target_path_as_posix(path_fs: VirtualFilesystem) -> None:
    path = path_fs.path("/some/file.txt")
    assert path.as_posix() == "/some/file.txt"

    path_fs.alt_separator = "\\"
    path = path_fs.path("\\some\\file.txt")
    assert path.exists()
    assert path.as_posix() == "/some/file.txt"


def test_target_path_as_uri(path_fs: VirtualFilesystem) -> None:
    path = path_fs.path("/some/file.txt")
    assert path.as_uri() == "file:///some/file.txt"

    path_fs.alt_separator = "\\"
    path = path_fs.path("\\some\\file.txt")
    assert path.as_uri() == "file:///some/file.txt"


def test_target_path_is_absolute(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/file.txt").is_absolute()
    assert not path_fs.path("some/file.txt").is_absolute()


def test_target_path_is_relative_to(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/dir/file.txt").is_relative_to("/some/dir")
    assert not path_fs.path("/some/dir/file.txt").is_relative_to("/some/other")


@pytest.mark.skipif(sys.version_info >= (3, 13), reason="deprecated on Python 3.13+")
def test_target_path_is_reserved(path_fs: VirtualFilesystem) -> None:
    # We currently do not have any reserved names for TargetPath
    assert not path_fs.path("CON").is_reserved()
    assert not path_fs.path("foo").is_reserved()


def test_target_path_join(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some").joinpath("file.txt") == path_fs.path("/some/file.txt")
    assert path_fs.path("/some") / "file.txt" == path_fs.path("/some/file.txt")


def test_target_path_match(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/file.txt").match("*.txt")
    assert not path_fs.path("/some/file.txt").match("*.csv")


def test_target_path_relative_to(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/dir/file.txt").relative_to("/some") == path_fs.path("dir/file.txt")


def test_target_path_with_name(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/file.txt").with_name("new_file.txt") == path_fs.path("/some/new_file.txt")


def test_target_path_with_stem(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/file.txt").with_stem("new_file") == path_fs.path("/some/new_file.txt")


def test_target_path_with_suffix(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/file.txt").with_suffix(".csv") == path_fs.path("/some/file.csv")


def test_target_path_stat(path_fs: VirtualFilesystem) -> None:
    stat_result = path_fs.path("/some/file.txt").stat()
    assert stat_result.st_mode == 0o100000
    assert stat_result.st_dev == id(path_fs)
    assert stat_result.st_nlink == 1

    stat_result = path_fs.path("/some").stat()
    assert stat_result.st_mode == 0o40000
    assert stat_result.st_dev == id(path_fs)
    assert stat_result.st_nlink == 1

    assert path_fs.path("/some/symlink.txt").stat() == path_fs.path("/some/dir/file.txt").stat()


def test_target_path_lstat(path_fs: VirtualFilesystem) -> None:
    stat_result = path_fs.path("/some/symlink.txt").lstat()
    assert stat_result != path_fs.path("/some/dir/file.txt").lstat()
    assert stat_result.st_mode == 0o120000


def test_target_path_exists(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/file.txt").exists()
    assert not path_fs.path("/some/other.txt").exists()


def test_target_path_glob(path_fs: VirtualFilesystem) -> None:
    assert list(path_fs.path("/some").glob("*.txt")) == [
        path_fs.path("/some/symlink.txt"),
        path_fs.path("/some/file.txt"),
    ]
    assert list(path_fs.path("/some").glob("*.csv")) == []


def test_target_path_rglob(path_fs: VirtualFilesystem) -> None:
    assert list(map(str, path_fs.path("/some").rglob("*.txt"))) == [
        "/some/symlink.txt",
        "/some/file.txt",
        "/some/dir/link.txt",
        "/some/dir/file.txt",
        "/some/dir/nested/file.txt",
    ]
    assert list(path_fs.path("/some").rglob("*.TXT")) == []
    assert list(path_fs.path("/some").rglob("*.csv")) == []

    with patch.object(path_fs, "case_sensitive", False):
        assert list(map(str, path_fs.path("/some").rglob("*.TXT"))) == [
            "/some/symlink.txt",
            "/some/file.txt",
            "/some/dir/link.txt",
            "/some/dir/file.txt",
            "/some/dir/nested/file.txt",
        ]


@pytest.mark.skipif(sys.version_info < (3, 12), reason="requires Python 3.12+")
def test_target_path_rglob_case_sensitive(path_fs: VirtualFilesystem) -> None:
    assert list(map(str, path_fs.path("/some").rglob("*.TXT", case_sensitive=False))) == [
        "/some/symlink.txt",
        "/some/file.txt",
        "/some/dir/link.txt",
        "/some/dir/file.txt",
        "/some/dir/nested/file.txt",
    ]


@pytest.mark.skipif(sys.version_info < (3, 13), reason="requires Python 3.13+")
def test_target_path_rglob_recurse_symlinks(path_fs: VirtualFilesystem) -> None:
    assert list(map(str, path_fs.path("/some").rglob("*.txt", recurse_symlinks=True))) == [
        "/some/symlink.txt",
        "/some/file.txt",
        "/some/dirlink/file.txt",
        "/some/dir/link.txt",
        "/some/dir/file.txt",
        "/some/dir/nested/file.txt",
    ]


def test_target_path_is_dir(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/dir").is_dir()
    assert not path_fs.path("/some/file.txt").is_dir()


def test_target_path_is_file(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/file.txt").is_file()
    assert not path_fs.path("/some/dir").is_file()


def test_target_path_is_mount(path_fs: VirtualFilesystem) -> None:
    assert not path_fs.path("/some").is_mount()

    mnt_vfs = VirtualFilesystem()
    mnt_vfs.makedirs("/foo")
    path_fs.mount("/mnt", mnt_vfs)

    assert path_fs.path("/mnt").is_mount()


def test_target_path_is_symlink(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/symlink.txt").is_symlink()
    assert not path_fs.path("/some/file.txt").is_symlink()
    assert not path_fs.path("/some/dir").is_symlink()


def test_target_path_is_junction(path_fs: VirtualFilesystem) -> None:
    assert not path_fs.path("/some").is_junction()

    mock_entry = Mock(spec=NtfsFilesystemEntry)
    mock_entry.dereference.return_value.is_mount_point.return_value = True

    path_fs.map_file_entry("/junction", mock_entry)
    assert path_fs.path("/junction").is_junction()


def test_target_path_is_socket(path_fs: VirtualFilesystem) -> None:
    assert not path_fs.path("/some/file.txt").is_socket()


def test_target_path_is_fifo(path_fs: VirtualFilesystem) -> None:
    assert not path_fs.path("/some/file.txt").is_fifo()


def test_target_path_is_block_device(path_fs: VirtualFilesystem) -> None:
    assert not path_fs.path("/some/file.txt").is_block_device()


def test_target_path_is_char_device(path_fs: VirtualFilesystem) -> None:
    assert not path_fs.path("/some/file.txt").is_char_device()


def test_target_path_iterdir(path_fs: VirtualFilesystem) -> None:
    assert list(path_fs.path("/some").iterdir()) == [
        path_fs.path("/some/dir"),
        path_fs.path("/some/symlink.txt"),
        path_fs.path("/some/dirlink"),
        path_fs.path("/some/file.txt"),
    ]


def test_target_path_walk(path_fs: VirtualFilesystem) -> None:
    assert list(path_fs.path("/some").walk()) == [
        (path_fs.path("/some"), ["dir"], ["symlink.txt", "dirlink", "file.txt"]),
        (path_fs.path("/some/dir"), ["nested"], ["link.txt", "file.txt"]),
        (path_fs.path("/some/dir/nested"), [], ["file.txt"]),
    ]


def test_target_path_open(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/file.txt").open("rb").read() == b"content"
    assert path_fs.path("/some/file.txt").open("r").read() == "content"


def test_target_path_read_bytes(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/file.txt").read_bytes() == b"content"


def test_target_path_read_text(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/file.txt").read_text() == "content"


def test_target_path_readlink(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/symlink.txt").readlink() == path_fs.path("/some/dir/file.txt")


def test_target_path_resolve(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/symlink.txt").resolve() == path_fs.path("/some/dir/file.txt")
    assert path_fs.path("/some/symlink.txt").resolve(strict=True) == path_fs.path("/some/dir/file.txt")
    assert path_fs.path("/some/foo").resolve() == path_fs.path("/some/foo")

    with pytest.raises(FileNotFoundError):
        assert path_fs.path("/some/foo").resolve(strict=True)

    with pytest.raises(FileNotFoundError):
        path_fs.path("/some/dir/link.txt").resolve(strict=True)

    with pytest.raises(NotADirectoryError):
        path_fs.path("/some/file.txt/other").resolve(strict=True)


def test_target_path_samefile(path_fs: VirtualFilesystem) -> None:
    assert path_fs.path("/some/symlink.txt").samefile(path_fs.path("/some/dir/file.txt"))
    assert not path_fs.path("/some/symlink.txt").samefile(path_fs.path("/some/file.txt"))


def test_target_path_errors(path_fs: VirtualFilesystem) -> None:
    # TargetPath sometimes emulates OSErrors to play nicely with pathlib, but other times
    # we raise our own FilesystemError variants. Ensure that all user-facing errors are our own.
    path_fs.symlink("symlink1", "symlink2")
    path_fs.symlink("symlink2", "symlink1")

    with pytest.raises(SymlinkRecursionError) as e:
        path_fs.path("symlink1/symlink2/symlink1").resolve()

    # This should raise from the final stat() call
    if sys.version_info >= (3, 10):
        assert [tb.name for tb in e.traceback[1:3]] == [
            "resolve",
            "stat",
        ]
    else:
        # In 3.9 there's no difference between these two
        assert [tb.name for tb in e.traceback[1:3]] == [
            "resolve",
            "resolve",
        ]

    with pytest.raises(SymlinkRecursionError) as e:
        path_fs.path("symlink1/symlink2/symlink1").resolve(strict=True)

    # This should raise from the inner realpath() call
    if sys.version_info >= (3, 10):
        assert [tb.frame.code.name for tb in e.traceback[1:3]] == [
            "resolve",
            "realpath",
        ]
    else:
        # In 3.9 there's no difference between these two
        assert [tb.frame.code.name for tb in e.traceback[1:3]] == [
            "resolve",
            "resolve",
        ]

    with pytest.raises(NotASymlinkError):
        path_fs.path("some/file.txt").readlink()

    with pytest.raises(NotADirectoryError):
        path_fs.path("some/file.txt/dir").stat()


def test_target_path_not_implemented(path_fs: VirtualFilesystem) -> None:
    # TargetPath can't do some things, such as write actions or stuff related to a "current" user or path
    # Ensure all those methods properly error
    with pytest.raises(NotImplementedError):
        assert path_fs.path().cwd()

    with pytest.raises(NotImplementedError):
        assert path_fs.path().home()

    with pytest.raises(NotImplementedError):
        assert path_fs.path().expanduser()

    with pytest.raises(NotImplementedError):
        assert path_fs.path().absolute()

    with pytest.raises(NotImplementedError):
        assert path_fs.path().owner()

    with pytest.raises(NotImplementedError):
        assert path_fs.path().group()

    with pytest.raises(NotImplementedError):
        assert path_fs.path().chmod(0o777)

    with pytest.raises(NotImplementedError):
        assert path_fs.path().lchmod(0o777)

    with pytest.raises(NotImplementedError):
        assert path_fs.path().rename("foo")

    with pytest.raises(NotImplementedError):
        assert path_fs.path().replace("foo")

    with pytest.raises(NotImplementedError):
        assert path_fs.path().symlink_to("foo")

    if sys.version_info >= (3, 10):
        with pytest.raises(NotImplementedError):
            assert path_fs.path().hardlink_to("foo")
    else:
        with pytest.raises(NotImplementedError):
            assert path_fs.path().link_to("foo")

    with pytest.raises(NotImplementedError):
        assert path_fs.path().mkdir()

    with pytest.raises(NotImplementedError):
        assert path_fs.path().rmdir()

    with pytest.raises(NotImplementedError):
        assert path_fs.path().touch()

    with pytest.raises(NotImplementedError):
        assert path_fs.path().unlink()

    with pytest.raises(NotImplementedError):
        assert path_fs.path().write_bytes(b"foo")

    with pytest.raises(NotImplementedError):
        assert path_fs.path().write_text("foo")


@pytest.mark.parametrize(
    ("path", "alt_separator", "result"),
    [
        ("/some/dir/some/file", "", ("/", "some", "dir", "some", "file")),
        ("/some/dir//some/file", "", ("/", "some", "dir", "some", "file")),
        ("/some/dir\\some/file", "", ("/", "some", "dir\\some", "file")),
        ("\\some\\dir\\some\\file", "\\", ("/", "some", "dir", "some", "file")),
        ("/some/dir/some/file", "\\", ("/", "some", "dir", "some", "file")),
        ("\\some\\dir\\\\some\\file", "\\", ("/", "some", "dir", "some", "file")),
        ("\\some\\dir/some\\file", "\\", ("/", "some", "dir", "some", "file")),
    ],
)
def test_pure_dissect_path__from_parts(path: str, alt_separator: str, result: tuple[str]) -> None:
    vfs = VirtualFilesystem(alt_separator=alt_separator)
    pure_dissect_path = fsutil.PureDissectPath(vfs, path)

    assert pure_dissect_path.parts == result


@pytest.mark.parametrize(
    ("alt_separator"),
    ["/", "\\"],
)
@pytest.mark.parametrize(
    ("case_sensitive"),
    [True, False],
)
def test_pure_dissect_path__from_parts_flavour(alt_separator: str, case_sensitive: bool) -> None:
    vfs = VirtualFilesystem(alt_separator=alt_separator, case_sensitive=case_sensitive)
    pure_dissect_path = fsutil.PureDissectPath(vfs, "/some/dir")

    obj = getattr(pure_dissect_path, "parser", None) or pure_dissect_path._flavour
    assert obj.altsep == alt_separator
    assert obj.case_sensitive == case_sensitive


def test_pure_dissect_path__from_parts_no_fs_exception() -> None:
    with pytest.raises(TypeError):
        fsutil.PureDissectPath(Mock(), "/some/dir")


@pytest.mark.parametrize(
    ("file_name", "compressor", "content"),
    [
        ("plain", lambda x: x, b"plain\ncontent"),
        ("comp.gz", gzip.compress, b"gzip\ncontent"),
        ("comp_gz", gzip.compress, b"gzip\ncontent"),
        ("comp.bz2", bz2.compress, b"bz2\ncontent"),
        ("comp_bz2", bz2.compress, b"bz2\ncontent"),
    ],
)
def test_open_decompress(file_name: str, compressor: Callable, content: bytes) -> None:
    vfs = VirtualFilesystem()
    fh = io.BytesIO(compressor(content))
    vfs.map_file_fh(file_name, fh)
    assert fsutil.open_decompress(vfs.path(file_name)).read() == content
    fh.seek(2)
    assert fsutil.open_decompress(fileobj=fh).read() == content


def test_open_decompress_text_modes() -> None:
    vfs = VirtualFilesystem()
    vfs.map_file_fh("test", io.BytesIO(b"zomgbbq"))

    fh = fsutil.open_decompress(vfs.path("test"))
    assert not isinstance(fh, io.TextIOWrapper)

    fh = fsutil.open_decompress(vfs.path("test"), "r")
    assert isinstance(fh, io.TextIOWrapper)
    assert fh.encoding == "UTF-8"
    assert fh.errors == "backslashreplace"

    fh = fsutil.open_decompress(vfs.path("test"), "r", errors=None)
    assert isinstance(fh, io.TextIOWrapper)
    assert fh.encoding == "UTF-8"
    assert fh.errors == "strict"

    fh = fsutil.open_decompress(vfs.path("test"), "r", encoding="ascii")
    assert isinstance(fh, io.TextIOWrapper)
    assert fh.encoding == "ascii"
    assert fh.errors == "backslashreplace"


def test_reverse_readlines() -> None:
    vfs = VirtualFilesystem()

    expected_range_reverse = ["99"] + [f"{i}\n" for i in range(98, -1, -1)]

    vfs.map_file_fh("file_n", io.BytesIO("\n".join(map(str, range(100))).encode()))
    assert list(fsutil.reverse_readlines(vfs.path("file_n").open("rt"))) == expected_range_reverse

    vfs.map_file_fh("file_r", io.BytesIO("\r".join(map(str, range(100))).encode()))
    assert list(fsutil.reverse_readlines(vfs.path("file_r").open("rt"))) == expected_range_reverse

    vfs.map_file_fh("file_rn", io.BytesIO("\r\n".join(map(str, range(100))).encode()))
    assert list(fsutil.reverse_readlines(vfs.path("file_rn").open("rt"))) == expected_range_reverse

    vfs.map_file_fh("file_multi", io.BytesIO("🦊\n🦊🦊\n🦊🦊🦊".encode()))
    assert list(fsutil.reverse_readlines(vfs.path("file_multi").open("rt"))) == ["🦊🦊🦊", "🦊🦊\n", "🦊\n"]

    vfs.map_file_fh("file_multi_long", io.BytesIO((("🦊" * 8000) + ("a" * 200) + "\n🦊🦊\n🦊🦊🦊").encode()))
    assert list(fsutil.reverse_readlines(vfs.path("file_multi_long").open("rt"))) == [
        "🦊🦊🦊",
        "🦊🦊\n",
        ("🦊" * 8000) + ("a" * 200) + "\n",
    ]

    vfs.map_file_fh("file_multi_long_single", io.BytesIO((("🦊" * 8000) + ("a" * 200)).encode()))
    assert list(fsutil.reverse_readlines(vfs.path("file_multi_long_single").open("rt"))) == [
        ("🦊" * 8000) + ("a" * 200)
    ]

    vfs.map_file_fh("empty", io.BytesIO(b""))
    assert list(fsutil.reverse_readlines(vfs.path("empty").open("rt"))) == []

    broken_content = (b"foobar\r\n" * 2) + (b"\xc2broken\r\n") + (b"barfoo\r\n" * 2)
    vfs.map_file_fh("file_multi_broken", io.BytesIO(broken_content))
    with pytest.raises(
        UnicodeDecodeError, match="'UTF-8' codec can't decode bytes in position 0-17: failed to decode line"
    ):
        assert list(fsutil.reverse_readlines(vfs.path("file_multi_broken").open("rt"))) == ["barfoo\n", "barfoo\n"]

    assert list(fsutil.reverse_readlines(vfs.path("file_multi_broken").open("rt", errors="backslashreplace"))) == [
        "barfoo\n",
        "barfoo\n",
        "\\xc2broken\n",
        "foobar\n",
        "foobar\n",
    ]


def test_reverse_read() -> None:
    """Test if we read the bytes of a file in reverse succesfully."""
    fs = VirtualFilesystem()

    fs.map_file_fh("file", io.BytesIO(b"1234567890"))
    assert list(fsutil.reverse_read(fs.path("file").open("rb"), chunk_size=2)) == [b"09", b"87", b"65", b"43", b"21"]

    fs.map_file_fh("large_emoji", io.BytesIO(("🐱" * 10_000).encode()))
    content = list(fsutil.reverse_read(fs.path("large_emoji").open("rb")))
    assert len(content) == 5
    assert len(content[0]) == 1024 * 8
    assert len(content[-1]) == 7232
    assert b"".join(content) == bytes(reversed(("🐱" * 10_000).encode()))


@pytest.fixture
def xattrs() -> dict[str, bytes]:
    return {"some_key": b"some_value"}


@pytest.fixture
def listxattr_spec(xattrs: dict[str, str]) -> dict[str, Any]:
    # listxattr() is only available on Linux
    attr_names = list(xattrs.keys())

    if hasattr(os, "listxattr"):
        spec = {
            "create": False,
            "autospec": True,
            "return_value": attr_names,
        }
    else:
        spec = {
            "create": True,
            "return_value": attr_names,
        }

    return spec


@pytest.fixture
def getxattr_spec(xattrs: dict[str, str]) -> dict[str, Any]:
    # getxattr() is only available on Linux
    attr_name = next(iter(xattrs.keys()))
    attr_value = xattrs.get(attr_name)

    if hasattr(os, "getxattr"):
        spec = {
            "create": False,
            "autospec": True,
            "return_value": attr_value,
        }
    else:
        spec = {
            "create": True,
            "return_value": attr_value,
        }

    return spec


@pytest.mark.parametrize(
    "follow_symlinks",
    [
        True,
        False,
    ],
)
def test_fs_attrs(
    xattrs: dict[str, bytes], listxattr_spec: dict[str, Any], getxattr_spec: dict[str, Any], follow_symlinks: bool
) -> None:
    with patch("os.listxattr", **listxattr_spec) as listxattr, patch("os.getxattr", **getxattr_spec) as getxattr:
        path = "/some/path"
        attr_name = next(iter(xattrs.keys()))

        assert fsutil.fs_attrs(path, follow_symlinks=follow_symlinks) == xattrs
        listxattr.assert_called_with(path, follow_symlinks=follow_symlinks)
        getxattr.assert_called_with(path, attr_name, follow_symlinks=follow_symlinks)


@contextmanager
def no_listxattr() -> Iterator[None]:
    if not hasattr(os, "listxattr"):
        yield
        return
    listxattr = os.listxattr
    try:
        del os.listxattr
        yield
    finally:
        os.listxattr = listxattr


def test_fs_attrs_no_os_listxattr() -> None:
    with no_listxattr():
        assert fsutil.fs_attrs("/some/path") == {}


def test_target_path_checks_dirfs(tmp_path: Path, target_win: Target) -> None:
    with tempfile.NamedTemporaryFile(dir=tmp_path, delete=False) as tf:
        tf.write(b"dummy")
        tf.close()

        tmpfile_name = Path(tf.name).name

        fs = DirectoryFilesystem(path=tmp_path)
        target_win.filesystems.add(fs)
        target_win.fs.mount("Z:\\", fs)
        assert target_win.fs.path(f"Z:\\{tmpfile_name}").is_file()
        assert not target_win.fs.path(f"Z:\\{tmpfile_name}\\some").exists()
        assert not target_win.fs.path(f"Z:\\{tmpfile_name}\\some").is_file()


def test_target_path_checks_mapped_dir(tmp_path: Path, target_win: Target) -> None:
    with tempfile.NamedTemporaryFile(dir=tmp_path, delete=False) as tf:
        tf.write(b"dummy")
        tf.close()

        tmpfile_name = Path(tf.name).name

        target_win.filesystems.entries[0].map_dir("test-dir", tmp_path)
        assert target_win.fs.path("C:\\test-dir\\").is_dir()
        assert not target_win.fs.path("C:\\test-dir\\").is_file()

        assert target_win.fs.path(f"C:\\test-dir\\{tmpfile_name}").is_file()
        assert not target_win.fs.path(f"C:\\test-dir\\{tmpfile_name}\\some").is_file()


def test_target_path_checks_virtual() -> None:
    vfs = VirtualFilesystem()
    vfs.map_file_entry("file", VirtualFile(vfs, "file", None))
    assert not vfs.path("file/test").exists()


def test_target_path_backslash_normalisation(target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path) -> None:
    with tempfile.NamedTemporaryFile(dir=tmp_path, delete=False) as tf:
        tf.write(b"dummy")
        tf.close()

        fs_win.map_dir("windows/system32/", tmp_path)
        fs_win.map_file("windows/system32/somefile.txt", tf.name)

        results = list(target_win.fs.path("/").glob("C:\\windows\\system32\\some*.txt"))
        assert len(results) == 1

        results = list(target_win.fs.path("/").glob("sysvol/windows/system32/some*.txt"))
        assert len(results) == 1


@pytest.fixture
def glob_fs() -> VirtualFilesystem:
    vfs = VirtualFilesystem()
    paths = [
        "foo/bar/bla",
        "moo/bar/bla",
        "bar/bla",
    ]
    files = [
        "file.txt",
        "file.ini",
        "other.txt",
    ]
    special_files = [
        "lololo",
        "system.dat",
        "data.tgz",
    ]

    for idx, path in enumerate(paths):
        vfs.makedirs(path)
        for file in files:
            vfs.map_file_entry(f"/{path}/{file}", VirtualFile(vfs, f"{path}/{file}", None))
        special_file = special_files[idx]
        vfs.map_file_entry(f"/{path}/{special_file}", VirtualFile(vfs, f"{path}/{special_file}", None))

    return vfs


@pytest.mark.parametrize(
    ("start_path", "pattern", "results"),
    [
        ("/", "foo/bar/bla/file.*", ["foo/bar/bla/file.ini", "foo/bar/bla/file.txt"]),
        ("/", "foo/bar/*/file.ini", ["foo/bar/bla/file.ini"]),
        ("/", "foo/bar/*/file.*", ["foo/bar/bla/file.ini", "foo/bar/bla/file.txt"]),
        ("/", "*/bar/bla/file.ini", ["foo/bar/bla/file.ini", "moo/bar/bla/file.ini"]),
        ("/", "*/bar/bla/*.ini", ["foo/bar/bla/file.ini", "moo/bar/bla/file.ini"]),
        ("/foo", "*/bla/file.ini", ["foo/bar/bla/file.ini"]),
        ("/foo", "*/bla/*.ini", ["foo/bar/bla/file.ini"]),
        ("/", "boo/bla/*", []),
    ],
)
def test_glob_ext(glob_fs: VirtualFilesystem, start_path: str, pattern: str, results: list[str]) -> None:
    start_entry = glob_fs.get(start_path)
    entries = fsutil.glob_ext(start_entry, pattern)

    entries = sorted([entry.path for entry in entries])
    assert entries == sorted(results)
