from __future__ import annotations

import stat
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest

from dissect.target.filesystem import VirtualFile, VirtualFilesystem
from dissect.target.helpers import fsutil
from dissect.target.loaders.tar import TarLoader
from dissect.target.plugins.filesystem.walkfs import WalkFsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture

    from dissect.target.target import Target


def test_walkfs_plugin(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_entry("/path/to/some/file", VirtualFile(fs_unix, "file", None))
    fs_unix.map_file_entry("/path/to/some/other/file.ext", VirtualFile(fs_unix, "file.ext", None))
    fs_unix.map_file_entry("/root_file", VirtualFile(fs_unix, "root_file", None))
    fs_unix.map_file_entry("/other_root_file.ext", VirtualFile(fs_unix, "other_root_file.ext", None))
    fs_unix.map_file_entry("/.test/test.txt", VirtualFile(fs_unix, "test.txt", None))
    fs_unix.map_file_entry("/.test/.more.test.txt", VirtualFile(fs_unix, ".more.test.txt", None))

    target_unix.add_plugin(WalkFsPlugin)

    results = sorted(target_unix.walkfs(), key=lambda r: r.path)
    assert len(results) == 14
    assert [r.path for r in results] == [
        "/",
        "/.test",
        "/.test/.more.test.txt",
        "/.test/test.txt",
        "/etc",
        "/other_root_file.ext",
        "/path",
        "/path/to",
        "/path/to/some",
        "/path/to/some/file",
        "/path/to/some/other",
        "/path/to/some/other/file.ext",
        "/root_file",
        "/var",
    ]


@pytest.mark.benchmark
def test_benchmark_walkfs(target_bare: Target, benchmark: BenchmarkFixture) -> None:
    """Benchmark walkfs performance on a small tar archive with ~500 files."""

    loader = TarLoader(Path(absolute_path("_data/loaders/containerimage/alpine-docker.tar")))
    loader.map(target_bare)
    target_bare.apply()

    result = benchmark(lambda: next(WalkFsPlugin(target_bare).walkfs()))

    assert result.path == "/"


def test_walkfs_suid(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we detect a SUID binary correctly in the WalkFS plugin."""

    vfile = VirtualFile(fs_unix, "binary", None)
    vfile.lstat = Mock()
    vfile.lstat.return_value = fsutil.stat_result([stat.S_IFREG | stat.S_ISUID, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    fs_unix.map_file_entry("/path/to/suid/binary", vfile)

    target_unix.add_plugin(WalkFsPlugin)

    results = list(target_unix.walkfs())
    assert len(results) == 7

    assert results[-1].path == "/path/to/suid/binary"
    assert results[-1].fs_types == ["virtual"]
    assert results[-1].mode == 34816
    assert results[-1].is_suid


def test_walkfs_xattr(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we parse xattrs correctly in the WalkFS plugin."""

    xattr1 = Mock()
    xattr1.name = "security.capability"
    xattr1.value = bytes.fromhex("010000010020f00000f00f0f")

    xattr2 = Mock()
    xattr2.name = "example.attr"
    xattr2.value = b"some value"

    vfile1 = VirtualFile(fs_unix, "file", None)
    vfile1.lattr = Mock()
    vfile1.lattr.return_value = [xattr1, xattr2]
    vfile1.fs.__type__ = "extfs"
    fs_unix.map_file_entry("/path/to/xattr1/file", vfile1)

    target_unix.add_plugin(WalkFsPlugin)

    results = list(target_unix.walkfs())
    assert len(results) == 7

    assert results[-1].path == "/path/to/xattr1/file"
    assert results[-1].fs_types == ["extfs"]
    assert results[-1].attr == ["security.capability=010000010020f00000f00f0f", "example.attr=736f6d652076616c7565"]
