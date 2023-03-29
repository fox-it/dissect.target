import bz2
import gzip
import io
import os
from unittest.mock import Mock

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers import fsutil


@pytest.mark.parametrize(
    ("path, alt_separator, result"),
    [
        ("/some/dir/some/file", "", "/some/dir/some/file"),
        ("/some/dir/some/file", "\\", "/some/dir/some/file"),
        ("\\some\\dir\\some\\file", "\\", "/some/dir/some/file"),
        ("/some///long\\\\dir/so\\//me\\file", "", "/some/long\\\\dir/so\\/me\\file"),
        ("/some///long\\\\dir/so\\//me\\file", "\\", "/some/long/dir/so/me/file"),
    ],
)
def test_helpers_fsutil_normalize(path, alt_separator, result):
    assert fsutil.normalize(path, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("args, alt_separator, result"),
    [
        (("/some/dir", "some/file"), "", "/some/dir/some/file"),
        (("/some/dir", "some/file"), "\\", "/some/dir/some/file"),
        (("\\some\\dir", "some\\file"), "\\", "/some/dir/some/file"),
        (("/some///long\\\\dir", "so\\//me\\file"), "", "/some/long\\\\dir/so\\/me\\file"),
        (("/some///long\\\\dir", "so\\//me\\file"), "\\", "/some/long/dir/so/me/file"),
    ],
)
def test_helpers_fsutil_join(args, alt_separator, result):
    assert fsutil.join(*args, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path, alt_separator, result"),
    [
        ("/some/dir/some/file", "", "/some/dir/some"),
        ("/some/dir/some/file", "\\", "/some/dir/some"),
        ("\\some\\dir\\some\\file", "\\", "/some/dir/some"),
        ("/some///long\\\\dir/so\\//me\\file", "", "/some/long\\\\dir/so\\"),
        ("/some///long\\\\dir/so\\//me\\file", "\\", "/some/long/dir/so/me"),
    ],
)
def test_helpers_fsutil_dirname(path, alt_separator, result):
    assert fsutil.dirname(path, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path, alt_separator, result"),
    [
        ("/some/dir/some/file", "", "file"),
        ("/some/dir/some/file", "\\", "file"),
        ("\\some\\dir\\some\\file", "\\", "file"),
        ("/some///long\\\\dir/so\\//me\\file", "", "me\\file"),
        ("/some///long\\\\dir/so\\//me\\file", "\\", "file"),
    ],
)
def test_helpers_fsutil_basename(path, alt_separator, result):
    assert fsutil.basename(path, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path, alt_separator, result"),
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
def test_helpers_fsutil_split(path, alt_separator, result):
    assert fsutil.split(path, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path, alt_separator, result"),
    [
        ("/some/dir", "", True),
        ("some/dir", "", False),
        ("\\some/dir", "", False),
        ("/some/dir", "\\", True),
        ("some/dir", "\\", False),
        ("\\some/dir", "\\", True),
    ],
)
def test_helpers_fsutil_isabs(path, alt_separator, result):
    assert fsutil.isabs(path, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path, alt_separator, result"),
    [
        ("/some/dir/../some/file", "", "/some/some/file"),
        ("/some/dir/../some/file", "\\", "/some/some/file"),
        ("\\some\\dir\\..\\some\\file", "\\", "/some/some/file"),
        ("/some///long\\..\\dir/so\\.//me\\file", "", "/some/long\\..\\dir/so\\./me\\file"),
        ("/some///long\\..\\dir/so\\.//me\\file", "\\", "/some/dir/so/me/file"),
    ],
)
def test_helpers_fsutil_normpath(path, alt_separator, result):
    assert fsutil.normpath(path, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path, cwd, alt_separator, result"),
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
def test_helpers_fsutil_abspath(path, cwd, alt_separator, result):
    assert fsutil.abspath(path, cwd=cwd, alt_separator=alt_separator) == result


@pytest.mark.parametrize(
    ("path, start, alt_separator, result"),
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
def test_helpers_fsutil_relpath(path, start, alt_separator, result):
    assert fsutil.relpath(path, start, alt_separator=alt_separator) == result


def test_helpers_fsutil_generate_addr():
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


def test_stat_result():
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

    my_stat = os.stat(__file__)
    st = fsutil.stat_result.copy(my_stat)
    assert st == my_stat


@pytest.mark.parametrize(
    ("path, alt_separator, result"),
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
def test_helpers_fsutil_pure_dissect_path__from_parts(path, alt_separator, result):
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
def test_helpers_fsutil_pure_dissect_path__from_parts_flavour(alt_separator, case_sensitive):
    vfs = VirtualFilesystem(alt_separator=alt_separator, case_sensitive=case_sensitive)
    pure_dissect_path = fsutil.PureDissectPath(vfs, "/some/dir")

    assert pure_dissect_path._flavour.altsep == alt_separator
    assert pure_dissect_path._flavour.case_sensitive == case_sensitive


def test_helpers_fsutil_pure_dissect_path__from_parts_no_fs_exception():
    with pytest.raises(TypeError):
        fsutil.PureDissectPath(Mock(), "/some/dir")


@pytest.mark.parametrize(
    ("file_name, compressor, content"),
    [
        ("plain", lambda x: x, b"plain\ncontent"),
        ("comp.gz", gzip.compress, b"gzip\ncontent"),
        ("comp_gz", gzip.compress, b"gzip\ncontent"),
        ("comp.bz2", bz2.compress, b"bz2\ncontent"),
        ("comp_bz2", bz2.compress, b"bz2\ncontent"),
    ],
)
def test_helpers_fsutil_open_decompress(file_name, compressor, content):
    vfs = VirtualFilesystem()
    vfs.map_file_fh(file_name, io.BytesIO(compressor(content)))
    assert fsutil.open_decompress(vfs.path(file_name)).read() == content


def test_helpers_fsutil_reverse_readlines():
    vfs = VirtualFilesystem()

    expected_range_reverse = ["99"] + [f"{i}\n" for i in range(98, -1, -1)]

    vfs.map_file_fh("file_n", io.BytesIO("\n".join(map(str, range(0, 100))).encode()))
    assert list(fsutil.reverse_readlines(vfs.path("file_n").open("rt"))) == expected_range_reverse

    vfs.map_file_fh("file_r", io.BytesIO("\r".join(map(str, range(0, 100))).encode()))
    assert list(fsutil.reverse_readlines(vfs.path("file_r").open("rt"))) == expected_range_reverse

    vfs.map_file_fh("file_rn", io.BytesIO("\r\n".join(map(str, range(0, 100))).encode()))
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
    assert list(fsutil.reverse_readlines(vfs.path("file_multi_long_single").open("rt"))) == [("🦊" * 8000) + ("a" * 200)]

    vfs.map_file_fh("empty", io.BytesIO(b""))
    assert list(fsutil.reverse_readlines(vfs.path("empty").open("rt"))) == []
