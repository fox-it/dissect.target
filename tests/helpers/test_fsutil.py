from __future__ import annotations

import bz2
import gzip
import inspect
import io
import os
import pathlib
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock, patch

import pytest
from flow.record.fieldtypes import path as flow_path

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
    from collections.abc import Callable, Iterator

    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("path", "sep", "result"),
    [
        pytest.param("/some/dir/some/file", "/", "/some/dir/some/file", id="posix"),
        pytest.param("", "/", "", id="posix-empty"),
        pytest.param("/", "/", "/", id="posix-root"),
        pytest.param("/some/dir/", "/", "/some/dir/", id="posix-trailing-sep"),
        pytest.param("//foo/bar", "/", "/foo/bar", id="posix-double-leading-sep"),
        pytest.param("/some/dir/../some/file", "/", "/some/dir/../some/file", id="posix-up-level"),
        pytest.param("/some/dir/./some/file", "/", "/some/dir/./some/file", id="posix-curdir"),
        pytest.param("/some///long\\\\dir/so\\//me\\file", "/", "/some/long\\\\dir/so\\/me\\file", id="posix-mixed"),
        pytest.param("\\some\\dir\\some\\file", "\\", "/some/dir/some/file", id="windows"),
        pytest.param("", "\\", "", id="windows-empty"),
        pytest.param("\\", "\\", "/", id="windows-root"),
        pytest.param("\\some\\dir\\", "\\", "/some/dir/", id="windows-trailing-sep"),
        pytest.param("/some/dir/some/file", "\\", "/some/dir/some/file", id="windows-alt"),
        pytest.param("/some/dir/../some/file", "\\", "/some/dir/../some/file", id="windows-up-level"),
        pytest.param("/some/dir/./some/file", "\\", "/some/dir/./some/file", id="windows-curdir"),
        pytest.param("/some///long\\\\dir/so\\//me\\file", "\\", "/some/long/dir/so/me/file", id="windows-mixed"),
        pytest.param("\\\\server\\share", "\\", "/server/share", id="windows-unc"),
    ],
)
def test_normalize(path: str, sep: str, result: str) -> None:
    """Test that normalizing a path with the given separator produces the expected result.

    Normalization should eliminate redundant separators and up-level references, and finally convert all separators
    to the POSIX style separator.
    """
    assert fsutil.normalize(path, sep=sep) == result


@pytest.mark.parametrize(
    ("args", "sep", "result"),
    [
        pytest.param(("/some/dir", "some/file"), "/", "/some/dir/some/file", id="posix"),
        pytest.param(("\\some\\dir", "some\\file"), "\\", "\\some\\dir\\some\\file", id="windows"),
        pytest.param(("/some/dir", "some/file"), "\\", "/some/dir\\some/file", id="windows-alt"),
        pytest.param(
            ("/some///long\\\\dir", "so\\//me\\file"), "/", "/some///long\\\\dir/so\\//me\\file", id="posix-mixed"
        ),
        pytest.param(
            ("/some///long\\\\dir", "so\\//me\\file"), "\\", "/some///long\\\\dir\\so\\//me\\file", id="windows-mixed"
        ),
        pytest.param(("/some/dir", "/some/other/file"), "/", "/some/other/file", id="posix-absolute"),
        pytest.param(("/some/dir", "/some/other/file"), "\\", "/some/other/file", id="windows-absolute"),
        pytest.param(
            ("C:\\some\\dir", "D:\\some\\file"), "\\", "C:\\some\\dir\\D:\\some\\file", id="windows-drive-absolute"
        ),
        pytest.param(("", "some/file"), "/", "some/file", id="posix-empty-first"),
        pytest.param(("/some/dir", ""), "/", "/some/dir/", id="posix-empty-second"),
        pytest.param(("/a", "b", "c"), "/", "/a/b/c", id="posix-three-components"),
        pytest.param(("\\a", "b", "c"), "\\", "\\a\\b\\c", id="windows-three-components"),
        pytest.param(("/some/dir/", "file"), "/", "/some/dir/file", id="posix-trailing-sep-first"),
        pytest.param(("\\some\\dir", "\\other"), "\\", "\\other", id="windows-abs"),
    ],
)
def test_join(args: str, sep: str, result: str) -> None:
    """Test that joining paths with the given separator produces the expected result.

    Joining a path should join as cleanly as possible without normalization. POSIX rules are always followed.
    No normalization is performed.
    """
    assert fsutil.join(*args, sep=sep) == result


@pytest.mark.parametrize(
    ("path", "sep", "result"),
    [
        pytest.param("/some/dir/some/file", "/", "/some/dir/some", id="posix"),
        pytest.param("/some", "/", "/", id="posix-no-dir"),
        pytest.param("some", "/", "", id="posix-relative"),
        pytest.param("/", "/", "/", id="posix-root"),
        pytest.param("", "/", "", id="posix-empty"),
        pytest.param("/some/dir/", "/", "/some/dir", id="posix-trailing-sep"),
        pytest.param("/some///long\\\\dir/so\\//me\\file", "/", "/some///long\\\\dir/so\\", id="posix-mixed"),
        pytest.param("\\some\\dir\\some\\file", "\\", "\\some\\dir\\some", id="windows"),
        pytest.param("/some/dir/some/file", "\\", "/some/dir/some", id="windows-alt"),
        pytest.param("", "\\", "", id="windows-empty"),
        pytest.param("C:", "\\", "", id="windows-root"),
        pytest.param("/C:", "\\", "", id="windows-root-alt"),
        pytest.param("/some///long\\\\dir/so\\//me\\file", "\\", "/some///long\\\\dir/so\\//me", id="windows-mixed"),
        pytest.param("c:\\some\\dir\\some\\file", "\\", "c:\\some\\dir\\some", id="windows-drive"),
        pytest.param("C:\\some", "\\", "C:", id="windows-drive-root"),
        pytest.param("C:some", "\\", "C:", id="windows-drive-root-no-sep"),
        pytest.param("\\sysvol\\some\\file", "\\", "sysvol\\some", id="windows-sysvol"),
    ],
)
def test_dirname(path: str, sep: str, result: str) -> None:
    """Test that getting the directory name of a path with the given separator produces the expected result."""
    assert fsutil.dirname(path, sep=sep) == result


@pytest.mark.parametrize(
    ("path", "sep", "result"),
    [
        pytest.param("/some/dir/some/file", "/", "file", id="posix"),
        pytest.param("/some", "/", "some", id="posix-no-dir"),
        pytest.param("some", "/", "some", id="posix-relative"),
        pytest.param("/", "/", "", id="posix-root"),
        pytest.param("", "/", "", id="posix-empty"),
        pytest.param("/some/dir/", "/", "", id="posix-trailing-sep"),
        pytest.param("/some///long\\\\dir/so\\//me\\file", "/", "me\\file", id="posix-mixed"),
        pytest.param("\\some\\dir\\some\\file", "\\", "file", id="windows"),
        pytest.param("/some/dir/some/file", "\\", "file", id="windows-alt"),
        pytest.param("", "\\", "", id="windows-empty"),
        pytest.param("C:", "\\", "C:", id="windows-root"),
        pytest.param("/C:", "\\", "C:", id="windows-root-alt"),
        pytest.param("\\some\\dir\\", "\\", "", id="windows-trailing-sep"),
        pytest.param("/some///long\\\\dir/so\\//me\\file", "\\", "file", id="windows-mixed"),
        pytest.param("c:\\some\\dir\\some\\file", "\\", "file", id="windows-drive"),
        pytest.param("\\sysvol\\some\\file", "\\", "file", id="windows-sysvol"),
    ],
)
def test_basename(path: str, sep: str, result: str) -> None:
    """Test that getting the base name of a path with the given separator produces the expected result."""
    assert fsutil.basename(path, sep=sep) == result


@pytest.mark.parametrize(
    ("path", "sep", "result"),
    [
        pytest.param("/some/dir/some/file", "/", ("/some/dir/some", "file"), id="posix"),
        pytest.param("/some", "/", ("/", "some"), id="posix-no-dir"),
        pytest.param("/", "/", ("/", ""), id="posix-root"),
        pytest.param("some/dir", "/", ("some", "dir"), id="posix-relative"),
        pytest.param("some", "/", ("", "some"), id="posix-relative-root"),
        pytest.param("", "/", ("", ""), id="posix-empty"),
        pytest.param("/some/dir/some/", "/", ("/some/dir/some", ""), id="posix-trailing-sep"),
        pytest.param("/some/dir/some\\", "/", ("/some/dir", "some\\"), id="posix-mixed"),
        pytest.param(
            "/some///long\\\\dir/so\\//me\\file",
            "/",
            ("/some///long\\\\dir/so\\", "me\\file"),
            id="posix-mixed-multi-sep",
        ),
        pytest.param("\\some\\dir\\some\\file", "\\", ("\\some\\dir\\some", "file"), id="windows"),
        pytest.param("/some/dir/some/file", "\\", ("/some/dir/some", "file"), id="windows-alt"),
        pytest.param("", "\\", ("", ""), id="windows-empty"),
        pytest.param("/some/dir/some/", "\\", ("/some/dir/some", ""), id="windows-trailing-sep"),
        pytest.param("\\some\\dir\\some\\", "\\", ("\\some\\dir\\some", ""), id="windows-trailing-sep-native"),
        pytest.param(
            "/some///long\\\\dir/so\\//me\\file", "\\", ("/some///long\\\\dir/so\\//me", "file"), id="windows-mixed"
        ),
        pytest.param("C:\\some", "\\", ("C:", "some"), id="windows-drive-root"),
        pytest.param("C:\\", "\\", ("", "C:"), id="windows-drive-trailing-sep"),
        pytest.param("C:", "\\", ("", "C:"), id="windows-drive-only"),
        pytest.param("C:some", "\\", ("C:", "some"), id="windows-drive-root-no-sep"),
        pytest.param("/C:/some", "\\", ("C:", "some"), id="windows-drive-root-alt"),
        pytest.param("\\\\server\\share\\file", "\\", ("\\\\server\\share", "file"), id="windows-unc"),
        pytest.param("\\sysvol\\some\\file", "\\", ("sysvol\\some", "file"), id="windows-sysvol"),
        pytest.param("\\efi\\some\\file", "\\", ("efi\\some", "file"), id="windows-efi"),
    ],
)
def test_split(path: str, sep: str, result: str) -> None:
    """Test that splitting a path with the given separator produces the expected result."""
    assert fsutil.split(path, sep=sep) == result


@pytest.mark.parametrize(
    ("path", "sep", "result"),
    [
        pytest.param("/foo/bar/file.txt", "/", ("/foo/bar/file", ".txt"), id="posix"),
        pytest.param("/foo.bar/file.tar.gz", "/", ("/foo.bar/file.tar", ".gz"), id="posix-multiple-dots"),
        pytest.param("C:\\foo\\bar\\file.txt", "\\", ("C:\\foo\\bar\\file", ".txt"), id="windows"),
        pytest.param("C:/foo.bar/file.txt", "\\", ("C:/foo.bar/file", ".txt"), id="windows-alt"),
        pytest.param("C:foo.bar/file.tar.gz", "\\", ("C:foo.bar/file.tar", ".gz"), id="windows-drive-no-sep"),
        pytest.param("/foo.bar/file", "/", ("/foo.bar/file", ""), id="posix-no-ext"),
        pytest.param("C:foo.bar/file", "\\", ("C:foo.bar/file", ""), id="windows-no-ext"),
        pytest.param("C:/foo.bar/file", "\\", ("C:/foo.bar/file", ""), id="windows-no-ext-dots-in-dir"),
        pytest.param(
            "C:/foo.bar/file.name.with.dots.txt",
            "\\",
            ("C:/foo.bar/file.name.with.dots", ".txt"),
            id="windows-multiple-dots",
        ),
        pytest.param("/foo/.hidden", "/", ("/foo/.hidden", ""), id="posix-dotfile"),
        pytest.param("/foo/.file.txt", "/", ("/foo/.file", ".txt"), id="posix-dotfile-with-ext"),
        pytest.param("/foo/.hidden", "\\", ("/foo/.hidden", ""), id="windows-dotfile"),
        pytest.param("/foo/.file.txt", "\\", ("/foo/.file", ".txt"), id="windows-dotfile-with-ext"),
        pytest.param("", "/", ("", ""), id="posix-empty"),
        pytest.param("", "\\", ("", ""), id="windows-empty"),
    ],
)
def test_splitext(path: str, sep: str, result: tuple[str, str]) -> None:
    """Test that splitting the extension of a path with the given separator produces the expected result."""
    assert fsutil.splitext(path, sep=sep) == result


@pytest.mark.parametrize(
    ("path", "sep", "result"),
    [
        pytest.param("/foo/bar/file.txt", "/", ("", "/foo/bar/file.txt"), id="posix"),
        pytest.param("C:/foo/bar/file.txt", "/", ("", "C:/foo/bar/file.txt"), id="posix-with-drive-letter"),
        pytest.param("", "/", ("", ""), id="posix-empty"),
        pytest.param("//host/share/file.txt", "/", ("", "//host/share/file.txt"), id="posix-unc"),
        pytest.param("C:\\foo\\bar\\file.txt", "\\", ("C:", "\\foo\\bar\\file.txt"), id="windows"),
        pytest.param("C:/foo/bar/file.txt", "\\", ("C:", "/foo/bar/file.txt"), id="windows-alt"),
        pytest.param("", "\\", ("", "\\"), id="windows-empty"),
        pytest.param("C:", "\\", ("C:", "\\"), id="windows-bare-drive"),
        pytest.param("C:file.txt", "\\", ("C:", "\\file.txt"), id="windows-drive-relative"),
        pytest.param("C:/file.txt", "\\", ("C:", "/file.txt"), id="windows-alt-root"),
        pytest.param(
            "\\C:\\some\\dir\\some\\file", "\\", ("C:", "\\some\\dir\\some\\file"), id="windows-leading-sep-drive"
        ),
        pytest.param("/C:/some/dir/some/file", "\\", ("C:", "/some/dir/some/file"), id="windows-alt-leading-sep-drive"),
        pytest.param("\\\\server\\share\\file.txt", "\\", ("\\\\server\\share", "\\file.txt"), id="windows-unc"),
        pytest.param("//server/share//file.txt", "\\", ("//server/share", "//file.txt"), id="windows-alt-unc"),
        pytest.param("\\sysvol\\file.txt", "\\", ("sysvol", "\\file.txt"), id="windows-sysvol"),
        pytest.param("\\efi\\some\\file", "\\", ("efi", "\\some\\file"), id="windows-efi"),
        pytest.param("\\winre\\some\\file", "\\", ("winre", "\\some\\file"), id="windows-winre"),
        pytest.param("\\$fs$\\some\\file", "\\", ("$fs$", "\\some\\file"), id="windows-fs"),
    ],
)
def test_splitdrive(path: str, sep: str, result: tuple[str, str]) -> None:
    """Test that splitting the drive of a path with the given separator produces the expected result.

    On POSIX-style paths, the drive is always empty. On Windows-style paths, we only split the drive if the path has
    a leading slash. Any name after the leading slash will be treated as the drive.
    If there's a second leading slash, it will be treated as a UNC path.
    """
    assert fsutil.splitdrive(path, sep=sep) == result


@pytest.mark.parametrize(
    ("path", "sep", "result"),
    [
        pytest.param("/foo/bar/file.txt", "/", ("", "/", "foo/bar/file.txt"), id="posix"),
        pytest.param("", "/", ("", "", ""), id="posix-empty"),
        pytest.param("some/path", "/", ("", "", "some/path"), id="posix-relative"),
        pytest.param("//host/share/file.txt", "/", ("", "//", "host/share/file.txt"), id="posix-unc"),
        pytest.param("C:\\foo\\bar\\file.txt", "\\", ("C:", "\\", "foo\\bar\\file.txt"), id="windows"),
        pytest.param("C:/foo/bar/file.txt", "\\", ("C:", "/", "foo/bar/file.txt"), id="windows-alt"),
        pytest.param("", "\\", ("", "\\", ""), id="windows-empty"),
        pytest.param("some/path", "\\", ("", "", "some/path"), id="windows-relative"),
        pytest.param("C:file.txt", "\\", ("C:", "\\", "file.txt"), id="windows-drive-relative"),
        pytest.param("C:/file.txt", "\\", ("C:", "/", "file.txt"), id="windows-alt-root"),
        pytest.param("c:", "\\", ("c:", "\\", ""), id="windows-drive-no-sep"),
        pytest.param(
            "\\C:\\some\\dir\\some\\file", "\\", ("C:", "\\", "some\\dir\\some\\file"), id="windows-leading-sep-drive"
        ),
        pytest.param(
            "/C:/some/dir/some/file", "\\", ("C:", "/", "some/dir/some/file"), id="windows-alt-leading-sep-drive"
        ),
        pytest.param("\\\\server\\share\\file.txt", "\\", ("\\\\server\\share", "\\", "file.txt"), id="windows-unc"),
        pytest.param("//server/share/file", "\\", ("//server/share", "/", "file"), id="windows-alt-unc"),
        pytest.param("\\sysvol\\file.txt", "\\", ("sysvol", "\\", "file.txt"), id="windows-sysvol"),
        pytest.param("sysvol", "\\", ("sysvol", "\\", ""), id="windows-sysvol-no-sep"),
        pytest.param("\\efi\\some\\file", "\\", ("efi", "\\", "some\\file"), id="windows-efi"),
        pytest.param("efi", "\\", ("efi", "\\", ""), id="windows-efi-no-sep"),
        pytest.param("\\winre\\some\\file", "\\", ("winre", "\\", "some\\file"), id="windows-winre"),
        pytest.param("\\$fs$\\some\\file", "\\", ("$fs$", "\\", "some\\file"), id="windows-fs"),
    ],
)
def test_splitroot(path: str, sep: str, result: tuple[str, str, str]) -> None:
    """Test that splitting the root of a path with the given separator produces the expected result.

    On POSIX-style paths, the drive is always empty. On Windows-style paths, we only split the drive if the path has
    a leading slash. Any name after the leading slash will be treated as the drive.
    If there's a second leading slash, it will be treated as a UNC path.
    """
    assert fsutil.splitroot(path, sep=sep) == result


@pytest.mark.parametrize(
    ("path", "sep", "result"),
    [
        pytest.param("/some/dir", "/", True, id="posix-abs"),
        pytest.param("some/dir", "/", False, id="posix-rel"),
        pytest.param("\\some/dir", "/", False, id="posix-rel-backslash"),
        pytest.param("", "/", False, id="posix-empty"),
        pytest.param("/", "/", True, id="posix-root"),
        pytest.param("\\", "/", False, id="posix-backslash"),
        pytest.param("\\some\\dir", "\\", True, id="windows-abs"),
        pytest.param("/some/dir", "\\", True, id="windows-abs-alt"),
        pytest.param("some/dir", "\\", False, id="windows-rel"),
        pytest.param("\\some/dir", "\\", True, id="windows-abs-mixed"),
        pytest.param("", "\\", False, id="windows-empty"),
        pytest.param("\\", "\\", True, id="windows-root"),
        pytest.param("/", "\\", True, id="windows-root-alt"),
        pytest.param("C:\\some\\dir", "\\", True, id="windows-drive"),
        pytest.param("C:/some/dir", "\\", True, id="windows-drive-alt-sep"),
        pytest.param("\\C:\\some\\dir", "\\", True, id="windows-leading-sep-drive"),
        pytest.param("/C:/some/dir", "\\", True, id="windows-leading-alt-sep-drive"),
        pytest.param("\\\\server\\share", "\\", True, id="windows-unc"),
        pytest.param("/sysvol/some/dir", "\\", True, id="windows-leading-sep-sysvol"),
        pytest.param("sysvol/some/dir", "\\", True, id="windows-sysvol"),
        pytest.param("efi/some/dir", "\\", True, id="windows-efi"),
        pytest.param("winre/some/dir", "\\", True, id="windows-winre"),
        pytest.param("$fs$/some/dir", "\\", True, id="windows-fs"),
    ],
)
def test_isabs(path: str, sep: str, result: str) -> None:
    """Test that checking if a path is absolute with the given separator produces the expected result."""
    assert fsutil.isabs(path, sep=sep) == result


@pytest.mark.parametrize(
    ("path", "sep", "result"),
    [
        pytest.param("/some/dir/../some/file", "/", "/some/some/file", id="posix"),
        pytest.param("some", "/", "some", id="posix-relative"),
        pytest.param("/", "/", "/", id="posix-root"),
        pytest.param("", "/", "", id="posix-empty"),
        pytest.param(".", "/", "", id="posix-curdir"),
        pytest.param("/some/../../../file", "/", "/file", id="posix-above-root"),
        pytest.param(
            "/some///long\\..\\dir/so\\.//me\\file", "/", "/some/long\\..\\dir/so\\./me\\file", id="posix-mixed"
        ),
        pytest.param("\\some\\dir\\..\\some\\file", "\\", "\\some\\some\\file", id="windows"),
        pytest.param("/some/dir/../some/file", "\\", "\\some\\some\\file", id="windows-alt"),
        pytest.param("", "\\", "", id="windows-empty"),
        pytest.param(".", "\\", "", id="windows-curdir"),
        pytest.param("/some///long\\..\\dir/so\\.//me\\file", "\\", "\\some\\dir\\so\\me\\file", id="windows-mixed"),
        pytest.param("C:/some", "\\", "C:\\some", id="windows-drive-no-up-level"),
        pytest.param("/C:/some", "\\", "C:\\some", id="windows-drive-leading-slash"),
        pytest.param("C:", "\\", "C:", id="windows-drive-root"),
        pytest.param("C:/", "\\", "C:", id="windows-drive-root-sep"),
        pytest.param("/C:/", "\\", "C:", id="windows-drive-root-sep-leading-slash"),
        pytest.param("C:\\some\\..\\file", "\\", "C:\\file", id="windows-drive-up-level"),
        pytest.param("C:\\some\\..\\..\\sysvol\\file", "\\", "sysvol\\file", id="windows-drive-up-level-sysvol"),
        pytest.param("\\sysvol\\some\\..\\file", "\\", "sysvol\\file", id="windows-sysvol"),
    ],
)
def test_normpath(path: str, sep: str, result: str) -> None:
    """Test that normalizing a path with the given separator produces the expected result.

    Empty paths should be normalized to a single separator on POSIX-style paths, and empty on Windows-style paths.

    Normalizes to the given separator.
    """
    assert fsutil.normpath(path, sep=sep) == result


@pytest.mark.parametrize(
    ("path", "cwd", "sep", "result"),
    [
        pytest.param("/some/dir", "", "/", "/some/dir", id="posix-abs"),
        pytest.param("some/dir", "", "/", "/some/dir", id="posix-rel"),
        pytest.param("\\some/dir", "", "/", "/\\some/dir", id="posix-rel-backslash"),
        pytest.param("\\some\\dir", "", "\\", "\\some\\dir", id="windows-abs"),
        pytest.param("some\\dir", "", "\\", "\\some\\dir", id="windows-rel"),
        pytest.param("/some/dir", "", "\\", "\\some\\dir", id="windows-abs-alt"),
        pytest.param("some/dir", "", "\\", "\\some\\dir", id="windows-rel-alt"),
        pytest.param("some/dir", "/", "\\", "\\some\\dir", id="windows-rel-alt-cwd"),
        pytest.param("/some/dir", "/my/cwd/", "/", "/some/dir", id="posix-abs-cwd"),
        pytest.param("\\some\\dir", "\\my\\cwd\\", "\\", "\\some\\dir", id="windows-abs-cwd"),
        pytest.param("some/dir", "/my/cwd/", "/", "/my/cwd/some/dir", id="posix-rel-cwd"),
        pytest.param("some\\dir", "/my/cwd/", "\\", "\\my\\cwd\\some\\dir", id="windows-rel-cwd"),
        pytest.param("some/dir", "/my\\cwd/", "/", "/my\\cwd/some/dir", id="posix-rel-cwd-backslash"),
        pytest.param("some\\dir", "/my\\cwd/", "\\", "\\my\\cwd\\some\\dir", id="windows-rel-cwd-mixed"),
        pytest.param("some/dir", "C:\\my\\cwd\\", "\\", "C:\\my\\cwd\\some\\dir", id="windows-rel-cwd-drive"),
        pytest.param("sysvol/dir", "", "\\", "sysvol\\dir", id="windows-sysvol-rel"),
    ],
)
def test_abspath(path: str, cwd: str, sep: str, result: str) -> None:
    """Test that getting the absolute path of a path with the given separator produces the expected result.

    Normalizes to the given separator.
    """
    assert fsutil.abspath(path, cwd=cwd, sep=sep) == result


@pytest.mark.parametrize(
    ("path", "start", "sep", "case_sensitive", "result"),
    [
        pytest.param("/some/dir/some/file", "/some/dir", "/", None, "some/file", id="posix"),
        pytest.param("/some/dir", "/some/dir", "/", None, "", id="posix-same-path"),
        pytest.param("/some/dir/file", "/some/other/file", "/", None, "../../dir/file", id="posix-sibling"),
        pytest.param("/some/dir/file", "/", "/", None, "some/dir/file", id="posix-from-root"),
        pytest.param(
            "/some///long\\\\dir/so\\//me\\file", "/some/long\\\\dir", "/", None, "so\\/me\\file", id="posix-mixed"
        ),
        pytest.param(
            "/some///long\\\\dir/so\\//me\\file",
            "/some/long/dir",
            "/",
            None,
            "../../long\\\\dir/so\\/me\\file",
            id="posix-mixed-parent",
        ),
        pytest.param("\\some\\dir\\some\\file", "\\some\\dir", "\\", None, "some\\file", id="windows"),
        pytest.param("/some/dir/some/file", "/some/dir", "\\", None, "some\\file", id="windows-alt"),
        pytest.param(
            "/some///long\\\\dir/so\\//me\\file", "/some/long/dir", "\\", True, "so\\me\\file", id="windows-mixed"
        ),
        pytest.param(
            "/some///long\\\\dir/so\\//me\\file",
            "/some/long\\\\dir",
            "\\",
            True,
            "so\\me\\file",
            id="windows-mixed-alt",
        ),
        pytest.param("C:/some/file", "D:/some/file", "\\", None, "..\\..\\..\\C:\\some\\file", id="windows-drive"),
        pytest.param(
            "/some/dir/some/file", "/SOME/DIR", "/", True, "../../some/dir/some/file", id="posix-case-sensitive"
        ),
        pytest.param("/some/dir/some/file", "/SOME/DIR", "/", False, "some/file", id="posix-case-insensitive"),
        pytest.param(
            "/some/dir/some/file", "/SOME/DIR", "\\", True, "..\\..\\some\\dir\\some\\file", id="windows-case-sensitive"
        ),
        pytest.param("/some/dir/some/file", "/SOME/DIR", "\\", False, "some\\file", id="windows-case-insensitive"),
    ],
)
def test_relpath(path: str, start: str, sep: str, case_sensitive: bool | None, result: str) -> None:
    """Test that getting the relative path of a path with the given separator produces the expected result.

    Normalizes to the given separator.
    """
    assert fsutil.relpath(path, start, sep=sep, case_sensitive=case_sensitive) == result


@pytest.mark.parametrize(
    ("paths", "sep", "case_sensitive", "result"),
    [
        pytest.param(["/some/dir/some/file", "/some/dir/some/other"], "/", None, "/some/dir/some", id="posix"),
        pytest.param(
            ["\\some\\dir\\some\\file", "\\some\\dir\\some\\other"], "\\", None, "\\some\\dir\\some", id="windows"
        ),
        pytest.param(
            ["/some/dir/some/file", "\\some\\dir\\some\\other"], "\\", None, "\\some\\dir\\some", id="windows-alt"
        ),
        pytest.param(["/some/dir/some/file", "/some/dir/other"], "/", None, "/some/dir", id="posix-two-shared"),
        pytest.param(["/some/dir/some/file", "/some/other"], "/", None, "/some", id="posix-one-shared"),
        pytest.param(["/some/dir/some/file", "/some/other"], "\\", None, "\\some", id="windows-alt-one-shared"),
        pytest.param(["/some/dir/some/file", "/other"], "/", None, "/", id="posix-none-shared"),
        pytest.param(["\\some\\dir\\some\\file", "/other"], "\\", None, "\\", id="windows-none-shared"),
        pytest.param(["/some/dir/some/file", "/other"], "\\", None, "\\", id="windows-alt-none-shared"),
        pytest.param(["/some/dir/some/file", "/SOME/DIR/SOME/OTHER"], "/", True, "/", id="posix-case-sensitive"),
        pytest.param(
            ["/some/DIR/some/file", "/SOME/DIR/SOME/OTHER"], "/", False, "/some/DIR/some", id="posix-case-insensitive"
        ),
        pytest.param(
            ["\\some\\dir\\some\\file", "\\SOME\\DIR\\SOME\\OTHER"],
            "\\",
            True,
            "\\",
            id="windows-case-sensitive",
        ),
        pytest.param(
            ["\\SOME\\dir\\SOME\\file", "\\SOME\\DIR\\SOME\\OTHER"],
            "\\",
            False,
            "\\SOME\\dir\\SOME",
            id="windows-case-insensitive",
        ),
        pytest.param(["/some/dir/file"], "/", None, "/some/dir/file", id="posix-single-path"),
        pytest.param(
            ["/some/dir/file", "/some/dir/other", "/some/dir/another"],
            "/",
            None,
            "/some/dir",
            id="posix-three-path-problem",
        ),
        pytest.param(
            ["\\some\\dir\\file", "\\some\\dir\\other", "\\some\\other"],
            "\\",
            None,
            "\\some",
            id="windows-three-path-problem",
        ),
    ],
)
def test_commonpath(paths: list[str], sep: str, case_sensitive: bool | None, result: str) -> None:
    """Test that getting the common path of a list of paths with the given separator produces the expected result.

    Normalizes to the given separator.
    """
    assert fsutil.commonpath(paths, sep=sep, case_sensitive=case_sensitive) == result


@pytest.mark.parametrize(
    ("path", "sep", "result"),
    [
        # These should all be the same after normalization
        pytest.param("/some/dir/some/file", "/", 194029235, id="posix"),
        pytest.param("\\some\\dir\\some\\file", "\\", 194029235, id="windows"),
        pytest.param("/some/dir/some/file", "\\", 194029235, id="windows-alt"),
        # This should be a different path
        pytest.param("\\some\\dir\\some\\file", "/", 1715326845, id="posix-backslash"),
    ],
)
def test_generate_addr(path: str, sep: str, result: int) -> None:
    """Test that generating an address for a path with the given separator produces the expected result."""
    vfs = VirtualFilesystem(sep=sep, altsep="/" if sep == "\\" else None)
    target_path = fsutil.TargetPath(vfs, path)

    assert fsutil.generate_addr(path, sep=sep) == result
    assert fsutil.generate_addr(target_path) == result


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


@pytest.mark.parametrize(
    ("sep", "altsep"),
    [("/", None), ("\\", "/")],
    ids=["posix", "windows"],
)
@pytest.mark.parametrize(
    ("case_sensitive"),
    [True, False],
    ids=["case-sensitive", "case-insensitive"],
)
def test_target_path_parser(sep: str, altsep: str, case_sensitive: bool) -> None:
    """Test that initializing a TargetPath with a VFS uses the VFS's separators."""
    vfs = VirtualFilesystem(sep=sep, altsep=altsep, case_sensitive=case_sensitive)

    # Direct initialization just uses the defaults
    path = fsutil.PureTargetPath("/some/dir")
    assert path.parser.sep == "/"
    assert path.parser.altsep is None

    # Initialization with a VFS should use the VFS's separators
    path = vfs.path("/some/dir")
    assert path.parser.sep == sep
    assert path.parser.altsep == altsep


def test_target_path_no_fs_exception() -> None:
    """Test that initializing a TargetPath without a filesystem raises the expected exception."""
    with pytest.raises(TypeError, match="invalid TargetPath initialization: missing filesystem"):
        fsutil.TargetPath(Mock(), "/some/dir")


# Test the rules set out by the way we treat paths:
# - Paths are normalized to POSIX-style with forward slashes, even on Windows-style filesystems
#   - This does not apply to the original path strings passed in (raw components), and thus forwarding to
#     something like flow.record path types should treat it like the proper style path
# - All POSIX-style paths are treated as absolute, and a slash will be prepended if not present
# - All Windows-style paths are treated as absolute, but will never display having a leading slash,
#   even if one is present in the original path string (e.g. /C:/some/path will be shown as C:/some/path)
# - Path joining behaves as if the paths are POSIX-style, even on Windows-style filesystems,
#   and so joining with an absolute path will always discard the all previous path components
#   (in contrast to Windows-style joining, which would only discard the previous components if the new component has
#   a drive letter or leading slash)
# - On Windows-style paths, attributes such as `.drive` work as expected
@pytest.mark.parametrize(
    ("sep", "paths", "parts", "string", "flow_string"),
    [
        pytest.param("/", [""], (), "", "", id="posix-empty"),
        pytest.param("/", ["/"], ("/",), "/", "/", id="posix-single-sep"),
        pytest.param("/", ["\\"], ("\\",), "\\", "\\", id="posix-single-backslash"),
        pytest.param("/", ["", "some/dir"], ("some", "dir"), "some/dir", "some/dir", id="posix-construct-empty"),
        pytest.param(
            "/",
            ["/some/path/to/file"],
            ("/", "some", "path", "to", "file"),
            "/some/path/to/file",
            "/some/path/to/file",
            id="posix",
        ),
        pytest.param(
            "/",
            ["some/dir/some/file"],
            ("some", "dir", "some", "file"),
            "some/dir/some/file",
            "some/dir/some/file",
            id="posix-relative",
        ),
        pytest.param(
            "/",
            ["/some/dir//some/file"],
            ("/", "some", "dir", "some", "file"),
            "/some/dir/some/file",
            "/some/dir/some/file",
            id="posix-double-sep",
        ),
        pytest.param(
            "/",
            ["/some/path/to/file/"],
            ("/", "some", "path", "to", "file"),
            "/some/path/to/file",
            "/some/path/to/file",
            id="posix-trailing-sep",
        ),
        # https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap04.html#tag_04_13
        pytest.param(
            "/",
            ["//some/path/to/file"],
            ("//", "some", "path", "to", "file"),
            "//some/path/to/file",
            "//some/path/to/file",
            id="posix-double-leading-sep",
        ),
        pytest.param(
            "/",
            ["///some/path/to/file"],
            ("/", "some", "path", "to", "file"),
            "/some/path/to/file",
            "/some/path/to/file",
            id="posix-triple-leading-sep",
        ),
        pytest.param(
            "/",
            ["/some/dir\\some/file"],
            ("/", "some", "dir\\some", "file"),
            "/some/dir\\some/file",
            "/some/dir\\some/file",
            id="posix-backslash",
        ),
        pytest.param(
            "/",
            ["\\some\\dir\\some\\file"],
            ("\\some\\dir\\some\\file",),
            "\\some\\dir\\some\\file",
            "\\some\\dir\\some\\file",
            id="posix-only-backslash",
        ),
        pytest.param(
            "/",
            ["/some/dir", "some/file"],
            ("/", "some", "dir", "some", "file"),
            "/some/dir/some/file",
            "/some/dir/some/file",
            id="posix-join-relative",
        ),
        pytest.param(
            "/",
            ["/some/path", "/to/file"],
            ("/", "to", "file"),
            "/to/file",
            "/to/file",
            id="posix-join-absolute",
        ),
        pytest.param("\\", [""], (), "", "", id="windows-empty"),
        pytest.param("\\", ["\\"], ("/",), "/", "\\", id="windows-single-sep"),
        pytest.param("\\", ["/"], ("/",), "/", "\\", id="windows-single-alt-sep"),
        pytest.param("\\", ["", "some\\dir"], ("some", "dir"), "some/dir", "some\\dir", id="windows-construct-empty"),
        pytest.param("\\", ["", "C:", "some"], ("C:", "some"), "C:/some", "C:\\some", id="windows-drive-construct"),
        pytest.param(
            "\\",
            ["\\some\\path\\to\\file"],
            ("/", "some", "path", "to", "file"),
            "/some/path/to/file",
            "\\some\\path\\to\\file",
            id="windows",
        ),
        pytest.param(
            "\\",
            ["/some/path/to/file"],
            ("/", "some", "path", "to", "file"),
            "/some/path/to/file",
            "\\some\\path\\to\\file",
            id="windows-alt",
        ),
        pytest.param(
            "\\",
            ["\\some\\dir\\\\some\\file"],
            ("/", "some", "dir", "some", "file"),
            "/some/dir/some/file",
            "\\some\\dir\\some\\file",
            id="windows-double-sep",
        ),
        pytest.param(
            "\\",
            ["\\some\\dir/some\\file"],
            ("/", "some", "dir", "some", "file"),
            "/some/dir/some/file",
            "\\some\\dir\\some\\file",
            id="windows-mixed-sep",
        ),
        pytest.param(
            "\\",
            ["C:\\some\\dir\\some\\file"],
            ("C:", "some", "dir", "some", "file"),
            "C:/some/dir/some/file",
            "C:\\some\\dir\\some\\file",
            id="windows-drive",
        ),
        pytest.param(
            "\\",
            ["C:/some/dir/some/file"],
            ("C:", "some", "dir", "some", "file"),
            "C:/some/dir/some/file",
            "C:\\some\\dir\\some\\file",
            id="windows-drive-alt",
        ),
        pytest.param(
            "\\",
            ["C:some/dir/some/file"],
            ("C:", "some", "dir", "some", "file"),
            "C:/some/dir/some/file",
            "C:\\some\\dir\\some\\file",
            id="windows-drive-no-sep",
        ),
        pytest.param(
            "\\",
            ["/C:some/dir/some/file"],
            ("C:", "some", "dir", "some", "file"),
            "C:/some/dir/some/file",
            "C:\\some\\dir\\some\\file",
            id="windows-drive-leading-sep",
        ),
        pytest.param(
            "\\",
            ["/C:/some/dir/some/file"],
            ("C:", "some", "dir", "some", "file"),
            "C:/some/dir/some/file",
            "C:\\some\\dir\\some\\file",
            id="windows-drive-leading-slash",
        ),
        pytest.param(
            "\\",
            ["C:"],
            ("C:",),
            "C:",
            "C:",
            id="windows-bare-drive",
        ),
        pytest.param(
            "\\",
            ["C:", "some/dir/some/file"],
            ("C:", "some", "dir", "some", "file"),
            "C:/some/dir/some/file",
            "C:\\some\\dir\\some\\file",
            id="windows-drive-join-relative",
        ),
        pytest.param(
            "\\",
            ["C:/", "some/dir/some/file"],
            ("C:", "some", "dir", "some", "file"),
            "C:/some/dir/some/file",
            "C:\\some\\dir\\some\\file",
            id="windows-drive-sep-join-relative",
        ),
        pytest.param(
            "\\",
            ["\\", "C:/some/dir/some/file"],
            ("C:", "some", "dir", "some", "file"),
            "C:/some/dir/some/file",
            "C:\\some\\dir\\some\\file",
            id="windows-bare-sep-join-drive",
        ),
        pytest.param(
            "\\",
            ["C:/some/dir", "some/file"],
            ("C:", "some", "dir", "some", "file"),
            "C:/some/dir/some/file",
            "C:\\some\\dir\\some\\file",
            id="windows-join-relative",
        ),
        pytest.param(
            "\\",
            ["C:/some/dir", "/sysvol/file"],
            ("sysvol", "file"),
            "sysvol/file",
            "sysvol\\file",
            id="windows-join-absolute",
        ),
        pytest.param(
            "\\",
            ["C:/some/dir", "D:/some/file"],
            ("C:", "some", "dir", "D:", "some", "file"),
            "C:/some/dir/D:/some/file",
            "C:\\some\\dir\\D:\\some\\file",
            id="windows-join-drive",
        ),
        pytest.param(
            "\\",
            ["C:/some/dir", "/D:/some/file"],
            ("D:", "some", "file"),
            "D:/some/file",
            "D:\\some\\file",
            id="windows-join-drive-abs",
        ),
        pytest.param(
            "\\",
            ["\\\\some\\share\\file"],
            ("//some/share", "file"),
            "//some/share/file",
            "\\\\some\\share\\file",
            id="windows-unc",
        ),
        pytest.param(
            "\\",
            ["//some/share/file"],
            ("//some/share", "file"),
            "//some/share/file",
            "\\\\some\\share\\file",
            id="windows-unc-alt",
        ),
        pytest.param(
            "\\",
            ["\\\\some\\share", "/sysvol/file"],
            ("sysvol", "file"),
            "sysvol/file",
            "sysvol\\file",
            id="windows-unc-join-absolute",
        ),
        pytest.param(
            "\\",
            ["C:/some/dir/some/file:stream"],
            ("C:", "some", "dir", "some", "file:stream"),
            "C:/some/dir/some/file:stream",
            "C:\\some\\dir\\some\\file:stream",
            id="windows-ads",
        ),
        pytest.param(
            "\\",
            ["\\Device\\HarddiskVolume1\\Windows\\System32\\backgroundTaskHost.exe"],
            ("/", "Device", "HarddiskVolume1", "Windows", "System32", "backgroundTaskHost.exe"),
            "/Device/HarddiskVolume1/Windows/System32/backgroundTaskHost.exe",
            "\\Device\\HarddiskVolume1\\Windows\\System32\\backgroundTaskHost.exe",
            id="windows-device",
        ),
    ],
)
def test_target_path(sep: str, paths: list[str], parts: tuple[str, ...], string: str, flow_string: str) -> None:
    """Test that TargetPath correctly parses and represents paths."""
    vfs = VirtualFilesystem(sep=sep, altsep="/" if sep == "\\" else None)
    path = vfs.path(*paths)
    assert path.parts == parts
    assert str(path) == string
    assert repr(path).startswith("TargetPath(")
    assert str(flow_path(path)) == flow_string


@pytest.mark.parametrize(
    ("sep", "path", "drive"),
    [
        pytest.param("/", "/some/file.txt", "", id="posix"),
        pytest.param("/", "C:/some/file.txt", "", id="posix-drive-letter"),
        pytest.param("\\", "\\sysvol\\file.txt", "sysvol", id="windows-sysvol-leading-sep"),
        pytest.param("\\", "C:some\\file.txt", "C:", id="windows-drive-letter-no-sep"),
        pytest.param("\\", "C:\\some\\file.txt", "C:", id="windows-drive-letter-with-sep"),
        pytest.param("\\", "\\\\server\\share\\file.txt", "//server/share", id="windows-unc-path"),
        pytest.param("\\", "\\\\?\\C:\\some\\file.txt", "//?/C:", id="windows-device-path-unc"),
        pytest.param("\\", "\\\\.\\C:\\some\\file.txt", "//./C:", id="windows-device-path-unc-alt"),
    ],
)
def test_target_path_drive(sep: str, path: str, drive: str) -> None:
    """Test that TargetPath correctly parses the drive component of paths."""
    vfs = VirtualFilesystem(sep=sep)
    assert vfs.path(path).drive == drive


@pytest.mark.parametrize(
    ("sep", "path", "root"),
    [
        pytest.param("/", "/some/file.txt", "/", id="posix"),
        pytest.param("/", "some/file.txt", "", id="posix-no-leading-sep"),
        pytest.param("\\", "\\sysvol\\file.txt", "/", id="windows-leading-sep"),
        pytest.param("\\", "some/file.txt", "", id="windows-no-leading-sep"),
        pytest.param("\\", "C:some\\file.txt", "/", id="windows-drive-letter-no-sep"),
        pytest.param("\\", "C:\\some\\file.txt", "/", id="windows-drive-letter-with-sep"),
        pytest.param("\\", "\\\\server\\share\\file.txt", "/", id="windows-unc-path"),
        pytest.param("\\", "\\\\?\\C:\\some\\file.txt", "/", id="windows-device-path-unc"),
        pytest.param("\\", "\\\\.\\C:\\some\\file.txt", "/", id="windows-device-path-unc-alt"),
    ],
)
def test_target_path_root(sep: str, path: str, root: str) -> None:
    """Test that TargetPath correctly parses the root component of paths."""
    vfs = VirtualFilesystem(sep=sep)
    assert vfs.path(path).root == root


@pytest.mark.parametrize(
    ("sep", "path", "anchor"),
    [
        pytest.param("/", "/some/file.txt", "/", id="posix"),
        pytest.param("\\", "\\sysvol\\file.txt", "sysvol/", id="windows-sysvol"),
        pytest.param("\\", "C:\\some\\file.txt", "C:/", id="windows-drive-letter"),
        pytest.param("\\", "\\\\server\\share\\file.txt", "//server/share/", id="windows-unc-path"),
        pytest.param("\\", "\\\\?\\C:\\some\\file.txt", "//?/C:/", id="windows-device-path-unc"),
        pytest.param("\\", "\\\\.\\C:\\some\\file.txt", "//./C:/", id="windows-device-path-unc-alt"),
    ],
)
def test_target_path_anchor(sep: str, path: str, anchor: str) -> None:
    """Test that TargetPath correctly parses the anchor component of paths."""
    vfs = VirtualFilesystem(sep=sep)
    assert vfs.path(path).anchor == anchor


@pytest.mark.parametrize(
    ("sep", "path", "parent"),
    [
        pytest.param("/", "/some/dir/file.txt", "/some/dir", id="posix"),
        pytest.param("/", "/some", "/", id="posix-root"),
        pytest.param("/", "/", "/", id="posix-bare"),
        pytest.param("\\", "\\some\\dir\\file.txt", "\\some\\dir", id="windows"),
        pytest.param("\\", "\\", "\\", id="windows-root"),
        pytest.param("\\", "c:\\some", "c:", id="windows-drive-letter-one-sep"),
        pytest.param("\\", "c:some", "c:", id="windows-drive-letter-no-sep"),
        pytest.param("\\", "c:", "", id="windows-drive-letter-only"),
        pytest.param("\\", "sysvol", "", id="windows-sysvol"),
    ],
)
def test_target_path_parent(sep: str, path: str, parent: str) -> None:
    """Test that TargetPath correctly parses the parent component of paths."""
    vfs = VirtualFilesystem(sep=sep)
    assert vfs.path(path).parent == vfs.path(parent)


def test_target_path_parents() -> None:
    """Test that TargetPath correctly parses the parents of paths."""
    vfs = VirtualFilesystem()
    path = vfs.path("/some/dir/file.txt")
    parents = list(path.parents)
    assert parents == [vfs.path("/some/dir"), vfs.path("/some"), vfs.path("/")]
    assert all(p._fs == vfs for p in parents)
    assert path.parents[1] == path.parents[-2] == vfs.path("/some")

    vfs = VirtualFilesystem(sep="\\")
    path = vfs.path("sysvol/some/file.txt")
    parents = list(path.parents)
    assert parents == [vfs.path("sysvol/some"), vfs.path("sysvol"), vfs.path("")]
    assert all(p._fs == vfs for p in parents)
    assert path.parents[1] == path.parents[-2] == vfs.path("sysvol")


@pytest.mark.parametrize(
    ("sep", "path", "name"),
    [
        pytest.param("/", "/some/file.txt", "file.txt", id="posix"),
        pytest.param("\\", "\\some\\file.txt", "file.txt", id="windows"),
        pytest.param("/", "/some/dir/", "dir", id="posix-trailing-separator"),
        pytest.param("\\", "\\some\\dir\\", "dir", id="windows-trailing-separator"),
        pytest.param("/", "/some", "some", id="posix-no-separator"),
        pytest.param("/", "/", "", id="posix-root"),
        pytest.param("\\", "\\", "", id="windows-root"),
        pytest.param("\\", "c:\\some", "some", id="windows-drive-letter-no-sep"),
        pytest.param("\\", "c:", "c:", id="windows-drive-letter-only"),
        pytest.param("\\", "sysvol", "sysvol", id="windows-sysvol"),
    ],
)
def test_target_path_name(sep: str, path: str, name: str) -> None:
    """Test that TargetPath correctly parses the name component of paths.

    We differentiate from pathlib by treating all parts of the path as path components.
    For example, for Windows-style paths, we treat the drive letter as part of the path (tail), and so
    the name of "C:/" would be "C:" instead of "" as pathlib would treat it.
    """
    vfs = VirtualFilesystem(sep=sep)
    assert vfs.path(path).name == name


def test_target_path_suffix() -> None:
    """Test that TargetPath correctly parses the suffix of paths."""
    vfs = VirtualFilesystem()
    assert vfs.path("/some/file.txt").suffix == ".txt"


def test_target_path_suffixes() -> None:
    """Test that TargetPath correctly parses the suffixes of paths."""
    vfs = VirtualFilesystem()
    assert vfs.path("/some/file.tar.gz").suffixes == [".tar", ".gz"]


def test_target_path_stem() -> None:
    """Test that TargetPath correctly parses the stem of paths."""
    vfs = VirtualFilesystem()
    assert vfs.path("/some/file.txt").stem == "file"


@pytest.mark.parametrize(
    ("sep", "path", "posix"),
    [
        pytest.param("/", "/some/file.txt", "/some/file.txt", id="posix"),
        pytest.param("\\", "\\sysvol\\file.txt", "sysvol/file.txt", id="windows"),
    ],
)
def test_target_path_as_posix(sep: str, path: str, posix: str) -> None:
    """Test that TargetPath correctly converts to a POSIX-style path string."""
    vfs = VirtualFilesystem(sep=sep)
    assert vfs.path(path).as_posix() == posix


@pytest.mark.parametrize(
    ("sep", "path", "uri"),
    [
        pytest.param("/", "/some/file.txt", "file:///some/file.txt", id="posix"),
        pytest.param("\\", "\\sysvol\\file.txt", "file:///sysvol/file.txt", id="windows"),
    ],
)
def test_target_path_as_uri(sep: str, path: str, uri: str) -> None:
    """Test that TargetPath correctly converts to a file URI."""
    vfs = VirtualFilesystem(sep=sep)
    assert vfs.path(path).as_uri() == uri


@pytest.mark.parametrize(
    ("sep", "uri", "path", "exception"),
    [
        pytest.param("/", "file:///some/file.txt", "/some/file.txt", None, id="posix"),
        pytest.param("\\", "file:///sysvol/file.txt", "/sysvol/file.txt", None, id="windows"),
        pytest.param(
            "/",
            "http:///some/file.txt",
            None,
            ValueError("URI does not start with 'file:'"),
            id="posix-invalid-protocol",
        ),
        pytest.param("/", "file://localhost/file.txt", "/file.txt", None, id="posix-localhost-authority"),
        pytest.param("/", "file:file.txt", None, ValueError("URI is not absolute"), id="posix-relative"),
    ],
)
def test_target_path_from_uri(sep: str, uri: str, path: str | None, exception: Exception | None) -> None:
    """Test that TargetPath.from_uri raises the expected exception, as it is unsupported."""
    vfs = VirtualFilesystem(sep=sep)

    if exception is not None:
        with pytest.raises(type(exception), match=re.escape(str(exception))):
            fsutil.TargetPath.from_uri(uri, fs=vfs)
    else:
        result = fsutil.TargetPath.from_uri(uri, fs=vfs)
        assert result == vfs.path(path)

    with pytest.raises(TypeError, match="missing 1 required keyword-only argument"):
        fsutil.TargetPath.from_uri(uri)

    with pytest.raises(ValueError, match="missing filesystem argument"):
        fsutil.TargetPath.from_uri(uri, fs=None)


def test_target_path_is_absolute() -> None:
    """Test that TargetPath correctly identifies absolute paths."""
    vfs = VirtualFilesystem()
    assert vfs.path("/some/file.txt").is_absolute()
    assert not vfs.path("some/file.txt").is_absolute()
    assert not vfs.path("sysvol\\file.txt").is_absolute()
    assert not vfs.path("c:\\file.txt").is_absolute()

    vfs.sep = "\\"
    vfs.altsep = "/"
    assert vfs.path("\\sysvol\\file.txt").is_absolute()
    assert vfs.path("sysvol\\file.txt").is_absolute()
    assert vfs.path("/sysvol/file.txt").is_absolute()
    assert vfs.path("c:\\file.txt").is_absolute()
    assert not vfs.path("abc/sysvol/file.txt").is_absolute()
    assert vfs.path("/abc/sysvol/file.txt").is_absolute()

    assert not vfs.path("/some/file.txt").relative_to("/some").is_absolute()


def test_target_path_is_relative_to() -> None:
    """Test that TargetPath correctly identifies relative paths."""
    vfs = VirtualFilesystem()
    assert vfs.path("/some/dir/file.txt").is_relative_to("/some/dir")
    assert not vfs.path("/some/dir/file.txt").is_relative_to("/some/other")


def test_target_path_join() -> None:
    """Test that TargetPath correctly joins paths."""
    vfs = VirtualFilesystem()
    assert vfs.path("/some").joinpath("file.txt") == vfs.path("/some/file.txt")
    assert vfs.path("/some") / "file.txt" == vfs.path("/some/file.txt")


def test_target_path_match() -> None:
    """Test that TargetPath correctly matches glob patterns."""
    vfs = VirtualFilesystem()
    assert vfs.path("/some/file.txt").match("*.txt")
    assert not vfs.path("/some/file.txt").match("*.csv")


def test_target_path_relative_to() -> None:
    """Test that TargetPath correctly computes relative paths."""
    vfs = VirtualFilesystem()
    path = vfs.path("/some/dir/file.txt").relative_to("/some")
    assert path == vfs.path("dir/file.txt")
    assert str(path) == "dir/file.txt"


@pytest.mark.parametrize(
    ("sep", "path", "name", "result"),
    [
        pytest.param("/", "/some/file.txt", "new_file.txt", "/some/new_file.txt", id="posix"),
        pytest.param("\\", "\\some\\file.txt", "new_file.txt", "\\some\\new_file.txt", id="windows"),
        pytest.param("\\", "C:\\", "file.txt", "/file.txt", id="windows-drive-letter-root"),
        pytest.param("\\", "C:", "file.txt", "/file.txt", id="windows-drive-letter-root-no-sep"),
        pytest.param("\\", "sysvol", "file.txt", "/file.txt", id="windows-sysvol-root"),
        pytest.param("\\", "sysvol", "c:", "c:", id="windows-sysvol-to-drive-letter"),
    ],
)
def test_target_path_with_name(sep: str, path: str, name: str, result: str) -> None:
    """Test that TargetPath correctly replaces the name of paths."""
    vfs = VirtualFilesystem(sep=sep)
    assert vfs.path(path).with_name(name) == vfs.path(result)


@pytest.mark.parametrize(
    ("sep", "path", "stem", "result"),
    [
        pytest.param("/", "/some/file.txt", "new_file", "/some/new_file.txt", id="posix"),
        pytest.param("\\", "\\some\\file.txt", "new_file", "\\some\\new_file.txt", id="windows"),
    ],
)
def test_target_path_with_stem(sep: str, path: str, stem: str, result: str) -> None:
    """Test that TargetPath correctly replaces the stem of paths."""
    vfs = VirtualFilesystem(sep=sep)
    assert vfs.path(path).with_stem(stem) == vfs.path(result)


@pytest.mark.parametrize(
    ("sep", "path", "suffix", "result"),
    [
        pytest.param("/", "/some/file.txt", ".csv", "/some/file.csv", id="posix"),
        pytest.param("\\", "\\some\\file.txt", ".csv", "\\some\\file.csv", id="windows"),
    ],
)
def test_target_path_with_suffix(sep: str, path: str, suffix: str, result: str) -> None:
    """Test that TargetPath correctly replaces the suffix of paths."""
    vfs = VirtualFilesystem(sep=sep)
    assert vfs.path(path).with_suffix(suffix) == vfs.path(result)


def test_target_path_hash() -> None:
    """Test that TargetPath hashing takes the correct case sensitivity into account."""
    vfs = VirtualFilesystem(sep="/")

    vfs.case_sensitive = True
    assert hash(vfs.path("/some/file.txt")) != hash(vfs.path("/some/FILE.TXT"))

    vfs.case_sensitive = False
    assert hash(vfs.path("/some/file.txt")) == hash(vfs.path("/some/FILE.TXT"))

    vfs.sep = "\\"

    vfs.case_sensitive = True
    assert hash(vfs.path("/some/file.txt")) != hash(vfs.path("/some/FILE.TXT"))

    vfs.case_sensitive = False
    assert hash(vfs.path("/some/file.txt")) == hash(vfs.path("/some/FILE.TXT"))


@pytest.fixture
def path_fs() -> VirtualFilesystem:
    vfs = VirtualFilesystem()

    vfs.makedirs("/some/dir")
    vfs.makedirs("/some/dir/nested")
    vfs.symlink("/some/dir/file.txt", "/some/symlink.txt")
    vfs.symlink("nonexistent", "/some/dir/link.txt")
    vfs.symlink("/some/dir/nested", "/some/dirlink")
    vfs.map_file_fh("/some/file.txt", io.BytesIO(b"content"))
    vfs.map_file_fh("/some/dir/file.txt", io.BytesIO())
    vfs.map_file_fh("/some/dir/nested/file.txt", io.BytesIO())

    return vfs


def test_target_path_stat(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly returns stat results."""
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
    """Test that TargetPath correctly returns lstat results."""
    stat_result = path_fs.path("/some/symlink.txt").lstat()
    assert stat_result != path_fs.path("/some/dir/file.txt").lstat()
    assert stat_result.st_mode == 0o120000


def test_target_path_exists(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly identifies existing and non-existing paths."""
    assert path_fs.path("/some/file.txt").exists()
    assert not path_fs.path("/some/other.txt").exists()


def test_target_path_glob(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly performs glob pattern matching."""
    assert list(path_fs.path("/some").glob("*.txt")) == [
        path_fs.path("/some/symlink.txt"),
        path_fs.path("/some/file.txt"),
    ]
    assert list(path_fs.path("/some").glob("*.csv")) == []


def test_target_path_rglob(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly performs recursive glob pattern matching."""
    assert next(path_fs.path("/some").rglob("file.txt"))
    assert list(map(str, path_fs.path("/some").rglob("*.txt"))) == [
        "/some/symlink.txt",
        "/some/file.txt",
        "/some/dir/link.txt",
        "/some/dir/file.txt",
        "/some/dir/nested/file.txt",
    ]
    assert list(path_fs.path("/some").rglob("*.TXT")) == []
    assert list(path_fs.path("/some").rglob("*.csv")) == []
    assert list(map(str, path_fs.path("/").rglob("*.*"))) == [
        "/some/symlink.txt",
        "/some/file.txt",
        "/some/dir/link.txt",
        "/some/dir/file.txt",
        "/some/dir/nested/file.txt",
    ]

    with patch.object(path_fs, "case_sensitive", False):
        assert list(map(str, path_fs.path("/some").rglob("*.TXT"))) == [
            "/some/symlink.txt",
            "/some/file.txt",
            "/some/dir/link.txt",
            "/some/dir/file.txt",
            "/some/dir/nested/file.txt",
        ]


def test_target_path_rglob_case_sensitive(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly performs case-sensitive recursive glob pattern matching."""
    assert next(path_fs.path("/some").rglob("file.txt", case_sensitive=True))
    assert list(map(str, path_fs.path("/some").rglob("*.TXT", case_sensitive=False))) == [
        "/some/symlink.txt",
        "/some/file.txt",
        "/some/dir/link.txt",
        "/some/dir/file.txt",
        "/some/dir/nested/file.txt",
    ]


def test_target_path_rglob_recurse_symlinks(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly performs recursive glob pattern matching with symlink recursion enabled."""
    assert list(map(str, path_fs.path("/some").rglob("*.txt", recurse_symlinks=True))) == [
        "/some/symlink.txt",
        "/some/file.txt",
        "/some/dirlink/file.txt",
        "/some/dir/link.txt",
        "/some/dir/file.txt",
        "/some/dir/nested/file.txt",
    ]


def test_target_path_backslash_normalisation(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Test that TargetPath correctly normalises backslashes in Windows-style paths."""
    fs_win.map_file_fh("windows/system32/somefile.txt", io.BytesIO(b"content"))

    assert target_win.fs.path("C:\\windows\\system32\\somefile.txt").name == "somefile.txt"
    assert target_win.fs.path("C:/windows/system32/somefile.txt").name == "somefile.txt"
    assert target_win.fs.path("/C:/windows/system32/somefile.txt").name == "somefile.txt"
    assert target_win.fs.path("/C:\\windows\\system32\\somefile.txt").name == "somefile.txt"
    assert target_win.fs.path("/").joinpath("C:\\windows\\system32\\somefile.txt").name == "somefile.txt"
    assert target_win.fs.path("").joinpath("C:\\windows\\system32\\somefile.txt").name == "somefile.txt"
    assert target_win.fs.path("C:\\windows").joinpath("system32\\somefile.txt").name == "somefile.txt"
    assert target_win.fs.path("C:/windows").joinpath("system32\\somefile.txt").name == "somefile.txt"

    results = list(target_win.fs.path("/").glob("C:\\windows\\system32\\some*.txt"))
    assert len(results) == 1

    results = list(target_win.fs.path("/").glob("sysvol/windows/system32/some*.txt"))
    assert len(results) == 1


def test_target_path_is_dir(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly identifies directories."""
    assert path_fs.path("/some/dir").is_dir()
    assert not path_fs.path("/some/file.txt").is_dir()


def test_target_path_is_file(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly identifies files."""
    assert path_fs.path("/some/file.txt").is_file()
    assert not path_fs.path("/some/dir").is_file()


def test_target_path_is_mount(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly identifies mount points."""
    assert not path_fs.path("/some").is_mount()

    mnt_vfs = VirtualFilesystem()
    mnt_vfs.makedirs("/foo")
    path_fs.mount("/mnt", mnt_vfs)

    assert path_fs.path("/mnt").is_mount()


def test_target_path_is_symlink(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly identifies symlinks."""
    assert path_fs.path("/some/symlink.txt").is_symlink()
    assert not path_fs.path("/some/file.txt").is_symlink()
    assert not path_fs.path("/some/dir").is_symlink()


def test_target_path_is_junction(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly identifies junctions."""
    assert not path_fs.path("/some").is_junction()

    mock_entry = Mock()
    mock_entry.__class__ = NtfsFilesystemEntry
    mock_entry.entry.is_mount_point.return_value = True

    path_fs.map_file_entry("/junction", mock_entry)
    assert path_fs.path("/junction").is_junction()


def test_target_path_is_socket(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly identifies sockets."""
    assert not path_fs.path("/some/file.txt").is_socket()


def test_target_path_is_fifo(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly identifies FIFOs."""
    assert not path_fs.path("/some/file.txt").is_fifo()


def test_target_path_is_block_device(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly identifies block devices."""
    assert not path_fs.path("/some/file.txt").is_block_device()


def test_target_path_is_char_device(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly identifies character devices."""
    assert not path_fs.path("/some/file.txt").is_char_device()


def test_target_path_iterdir(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly iterates directory entries."""
    assert list(path_fs.path("/some").iterdir()) == [
        path_fs.path("/some/dir"),
        path_fs.path("/some/symlink.txt"),
        path_fs.path("/some/dirlink"),
        path_fs.path("/some/file.txt"),
    ]


def test_target_path_iterdir_win(target_win: Target) -> None:
    """Test that TargetPath correctly iterates directory entries on Windows, including drive letters and sysvol."""
    entries = sorted(target_win.fs.path("/").iterdir())
    assert str(entries[0]) == "c:"
    assert str(entries[1]) == "sysvol"


def test_target_path_walk(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly walks directories."""
    assert list(path_fs.path("/some").walk()) == [
        (path_fs.path("/some"), ["dir"], ["symlink.txt", "dirlink", "file.txt"]),
        (path_fs.path("/some/dir"), ["nested"], ["link.txt", "file.txt"]),
        (path_fs.path("/some/dir/nested"), [], ["file.txt"]),
    ]


@pytest.mark.parametrize(
    ("sep", "path", "absolute"),
    [
        pytest.param("/", "/some/file.txt", "/some/file.txt", id="posix"),
        pytest.param("/", "some/file.txt", "/some/file.txt", id="posix-relative"),
        pytest.param("\\", "\\sysvol\\file.txt", "sysvol/file.txt", id="windows"),
        pytest.param("\\", "sysvol\\file.txt", "sysvol/file.txt", id="windows-relative"),
        pytest.param("\\", "C:", "C:", id="windows-drive-letter-only"),
        pytest.param("\\", "sysvol", "sysvol", id="windows-sysvol-only"),
    ],
)
def test_target_path_absolute(sep: str, path: str, absolute: str) -> None:
    """Test that TargetPath correctly returns absolute paths."""
    vfs = VirtualFilesystem(sep=sep)
    assert vfs.path(path).absolute().is_absolute()
    assert str(vfs.path(path).absolute()) == absolute


def test_target_path_open(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly opens files."""
    # Default is to open in binary mode
    assert path_fs.path("/some/file.txt").open().read() == b"content"
    assert path_fs.path("/some/file.txt").open("rb").read() == b"content"
    assert path_fs.path("/some/file.txt").open("r").read() == "content"


def test_target_path_read_bytes(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly reads bytes from files."""
    assert path_fs.path("/some/file.txt").read_bytes() == b"content"


def test_target_path_read_text(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly reads text from files."""
    assert path_fs.path("/some/file.txt").read_text() == "content"


def test_target_path_readlink(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly reads symlink targets."""
    assert path_fs.path("/some/symlink.txt").readlink() == path_fs.path("/some/dir/file.txt")


def test_target_path_resolve(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly resolves paths."""
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
    """Test that TargetPath correctly identifies when two paths refer to the same file."""
    assert path_fs.path("/some/symlink.txt").samefile(path_fs.path("/some/dir/file.txt"))
    assert not path_fs.path("/some/symlink.txt").samefile(path_fs.path("/some/file.txt"))


def test_target_path_errors(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly raises errors for various invalid operations."""
    # TargetPath sometimes emulates OSErrors to play nicely with pathlib, but other times
    # we raise our own FilesystemError variants. Ensure that all user-facing errors are our own.
    path_fs.symlink("symlink1", "symlink2")
    path_fs.symlink("symlink2", "symlink1")

    assert path_fs.path("symlink1/symlink2/symlink1").resolve() == path_fs.path("/symlink1/symlink2/symlink1")

    with pytest.raises(SymlinkRecursionError) as e:
        path_fs.path("symlink1/symlink2/symlink1").resolve(strict=True)

    # This should raise from the inner realpath() call
    assert [tb.frame.code.name for tb in e.traceback[1:3]] == [
        "resolve",
        "realpath",
    ]

    with pytest.raises(NotASymlinkError):
        path_fs.path("some/file.txt").readlink()

    with pytest.raises(NotADirectoryError):
        path_fs.path("some/file.txt/dir").stat()


def test_target_path_get(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath.get() correctly retrieves the underlying filesystem entry, and properly caches it."""
    p = path_fs.path("/some/file.txt")
    assert not hasattr(p, "_entry")

    entry = p.get()
    assert entry is p._entry

    p = next(path_fs.path("/some").iterdir())
    assert not hasattr(p, "_entry")
    assert hasattr(p, "_info")
    assert p._info._entry is not None

    entry = p.get()
    assert entry is p._entry

    with (
        patch.object(path_fs, "get", side_effect=Exception("Test exception")),
        pytest.raises(Exception, match="Test exception"),
    ):
        path_fs.path("/some/file.txt").get()


def test_target_path_not_implemented(path_fs: VirtualFilesystem) -> None:
    """Test that TargetPath correctly raises NotImplementedError for methods that are not supported."""
    # TargetPath can't do some things, such as write actions or stuff related to a "current" user or path
    # Ensure all those methods properly error
    with pytest.raises(NotImplementedError):
        assert path_fs.path().cwd()

    with pytest.raises(NotImplementedError):
        assert path_fs.path().home()

    with pytest.raises(NotImplementedError):
        assert path_fs.path().expanduser()

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

    with pytest.raises(NotImplementedError):
        assert path_fs.path().hardlink_to("foo")

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


def test_target_path_overrides() -> None:
    """Test that TargetPath provides an override for all public methods of pathlib.Path."""
    stdlib = {
        name
        for name, _ in inspect.getmembers(pathlib.Path)
        if (not name.startswith("_")) or name.startswith("__")  # public members only
    }
    target_path_methods = {name for name, _ in inspect.getmembers(fsutil.TargetPath)}
    assert len(stdlib - target_path_methods) == 0, (
        f"TargetPath is missing overrides for: {stdlib - target_path_methods}"
    )


def test_target_path_checks_dirfs(tmp_path: Path, target_win: Target) -> None:
    """Test that TargetPath correctly checks for files and directories in a mapped DirectoryFilesystem on Windows."""
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
    """Test that TargetPath correctly checks for files and directories in a mapped directory on Windows."""
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
    """Test that TargetPath correctly checks for files and directories in a mapped virtual file on Windows."""
    vfs = VirtualFilesystem()
    vfs.map_file_entry("file", VirtualFile(vfs, "file", None))
    assert not vfs.path("file/test").exists()


@pytest.mark.parametrize(
    ("file_name", "compressor", "content"),
    [
        pytest.param("plain", lambda x: x, b"plain\ncontent", id="plain"),
        pytest.param("comp.gz", gzip.compress, b"gzip\ncontent", id="gzip"),
        pytest.param("comp_gz", gzip.compress, b"gzip\ncontent", id="gzip-underscore"),
        pytest.param("comp.bz2", bz2.compress, b"bz2\ncontent", id="bz2"),
        pytest.param("comp_bz2", bz2.compress, b"bz2\ncontent", id="bz2-underscore"),
    ],
)
def test_open_decompress(file_name: str, compressor: Callable, content: bytes) -> None:
    vfs = VirtualFilesystem()
    fh = io.BytesIO(compressor(content))
    vfs.map_file_fh(file_name, fh)
    assert fsutil.open_decompress(vfs.path(file_name)).read() == content
    fh.seek(2)
    assert fsutil.open_decompress(fileobj=fh).read() == content


@pytest.mark.parametrize(
    ("compressor", "mock_bool_name"),
    [
        pytest.param(fsutil.lzma.compress, "HAS_XZ", id="xz"),
        pytest.param(fsutil.bz2.compress, "HAS_BZ2", id="bz2"),
        pytest.param(fsutil.zstd.compress, "HAS_ZSTD", id="zstd"),
    ],
)
def test_open_decompress_missing_module(
    compressor: Callable, mock_bool_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    vfs = VirtualFilesystem()
    fh = io.BytesIO(compressor(b"hello world"))
    vfs.map_file_fh("compressed_file", fh)

    with monkeypatch.context() as m:
        m.setattr(f"{fsutil.__name__}.{mock_bool_name}", False)
        with pytest.raises(RuntimeError, match=r".* compression detected, but missing optional python module"):
            fsutil.open_decompress(vfs.path("compressed_file"))


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

    vfs.map_file_fh("empty", io.BytesIO())
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
    content = list(fsutil.reverse_read(fs.path("large_emoji").open("rb"), chunk_size=8192))
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
        pytest.param(True, id="follow-symlinks"),
        pytest.param(False, id="no-follow-symlinks"),
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
        pytest.param("/", "foo/bar/bla/file.*", ["foo/bar/bla/file.ini", "foo/bar/bla/file.txt"], id="wildcard-ext"),
        pytest.param("/", "foo/bar/*/file.ini", ["foo/bar/bla/file.ini"], id="wildcard-dir"),
        pytest.param(
            "/", "foo/bar/*/file.*", ["foo/bar/bla/file.ini", "foo/bar/bla/file.txt"], id="wildcard-dir-and-ext"
        ),
        pytest.param(
            "/", "*/bar/bla/file.ini", ["foo/bar/bla/file.ini", "moo/bar/bla/file.ini"], id="wildcard-root-dir"
        ),
        pytest.param(
            "/", "*/bar/bla/*.ini", ["foo/bar/bla/file.ini", "moo/bar/bla/file.ini"], id="wildcard-root-dir-ext"
        ),
        pytest.param("/foo", "*/bla/file.ini", ["foo/bar/bla/file.ini"], id="subdir-wildcard-dir"),
        pytest.param("/foo", "*/bla/*.ini", ["foo/bar/bla/file.ini"], id="subdir-wildcard-dir-ext"),
        pytest.param("/", "boo/bla/*", [], id="no-match"),
    ],
)
def test_glob_ext(glob_fs: VirtualFilesystem, start_path: str, pattern: str, results: list[str]) -> None:
    start_entry = glob_fs.get(start_path)
    entries = fsutil.glob_ext(start_entry, pattern)

    entries = sorted([entry.path for entry in entries])
    assert entries == sorted(results)
