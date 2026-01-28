from __future__ import annotations

import stat
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest

from dissect.target.filesystem import VirtualFile, VirtualFilesystem
from dissect.target.helpers import fsutil
from dissect.target.loaders.tar import TarLoader
from dissect.target.plugins.filesystem.walkfs import WalkFsPlugin, get_disk_serial
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

    results = list(target_unix.walkfs(capability=True))
    assert len(results) == 8

    assert results[-2].path == "/path/to/xattr1/file"
    assert results[-2].fs_types == ["extfs"]
    assert results[-2].attr == ["security.capability=010000010020f00000f00f0f", "example.attr=736f6d652076616c7565"]

    assert results[-1].mtime
    assert results[-1].permitted == ["CAP_NET_RAW", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE"]
    assert results[-1].inheritable == [
        "CAP_NET_ADMIN",
        "CAP_NET_RAW",
        "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",
        "CAP_SYS_MODULE",
        "CAP_SYS_RAWIO",
        "CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE",
        "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME",
        "CAP_SYS_TTY_CONFIG",
        "CAP_MKNOD",
    ]
    assert results[-1].effective
    assert results[-1].root_id is None


def test_get_disk_serial_no_serial() -> None:
    """Test get_disk_serial when the `serial` attribute is missing."""

    vfs = VirtualFilesystem()
    vfs.volume = Mock(vs=Mock(serial="A1B2C3D4"))
    assert get_disk_serial(vfs) == "A1B2C3D4"


def test_get_disk_serial() -> None:
    """Test get_disk_serial when a serial number is available."""

    vfs = VirtualFilesystem()
    # initialize the Volume with vs as an empty object (no attributes)
    vfs.volume = Mock(vs=object())
    assert get_disk_serial(vfs) is None
