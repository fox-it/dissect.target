from __future__ import annotations

import tempfile
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem, VirtualFile, LayerFilesystem
from dissect.target.plugins.filesystem.mywalkfs import MyWalkPlugin
from tests._utils import absolute_path
from unittest.mock import Mock
from dissect.target.helpers import fsutil
from datetime import datetime, timezone
import stat

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target

#@pytest.fixture
# def target_mywalkfs(target_default: Target) -> Target:
#     vfs = VirtualFilesystem()
#     vfs.map_file_fh("test_file", BytesIO(b"test string"))
#     vfs.map_file_fh("/test/dir/to/test_file", BytesIO(b"test string"))
#     vfs.map_file_fh("should_not_hit", BytesIO(b"this is another file."))
#     target_default.fs.mount("/", vfs)
#     target_default.add_plugin(MyWalkPlugin)
#     return target_default
@pytest.fixture
def target_mywalkfs(target_unix: Target) -> Target:
    fs_unix = VirtualFilesystem()
    target_unix.fs.mount("/", fs_unix)
    target_unix.add_plugin(MyWalkPlugin)

    return target_unix


def test_basic_attributes_file(target_mywalkfs: Target) -> None:

    vfile = VirtualFile(target_mywalkfs.fs, "binary", BytesIO(b"test string"))
    vfile.lstat = Mock()
    base_stats = [
        stat.S_IFREG | stat.S_ISUID | 0o644,  # 0: st_mode (File + SUID + rw-r--r--)
        12345,  # 1: st_ino (Ino)
        0,  # 2: st_dev
        1,  # 3: st_nlink
        1000,  # 4: st_uid (User ID)
        1000,  # 5: st_gid (Group ID)
        8192,  # 6: st_size (8KB)
        1709300000,  # 7: _st_atime (Access time epoch)
        1709301000,  # 8: _st_mtime (Modify time epoch)
        1709302000,  # 9: _st_ctime (Change time epoch)
        None,  # 10: st_atime
        None,  # 11: st_mtime
        None,  # 12: st_ctime
        None,  # 13: st_atime_ns
        None,  # 14: st_mtime_ns
        None,  # 15: st_ctime_ns
        4096,  # 16: st_blksize
        16,  # 17: st_blocks
        0,  # 18: st_rdev
        0,  # 19: st_flags
        0,  # 20: st_gen
        1709200000,  # 21: st_birthtime (Creation time epoch -> btime)
    ]
    vfile.lstat.return_value = fsutil.stat_result(base_stats)
    target_mywalkfs.fs.map_file_entry("/path/to/suid/binary", vfile)

    results = list(target_mywalkfs.mywalkfs())

    record = results[4]

    assert len(results) == 5

    assert record.atime == datetime.fromtimestamp(1709300000, tz=timezone.utc)
    assert record.mtime == datetime.fromtimestamp(1709301000, tz=timezone.utc)
    assert record.ctime == datetime.fromtimestamp(1709302000, tz=timezone.utc)
    assert record.btime == datetime.fromtimestamp(1709200000, tz=timezone.utc)

    assert record.ino == 12345
    assert record.size == 8192

    assert record.mode == (stat.S_IFREG | stat.S_ISUID | 0o644)
    assert record.uid == 1000
    assert record.gid == 1000

    assert record.is_suid == True

def test_symlink(target_mywalkfs: Target) -> None:
    target_mywalkfs.fs.map_file_fh("/path/to/suid/binary", BytesIO(b"test string"))
    target_mywalkfs.fs.symlink("/path/to/suid/binary", "/symlinkfile")

    results = list(target_mywalkfs.mywalkfs())
    record = results[5]

    assert record.type == "Symlink"

def test_directory(target_mywalkfs: Target) -> None:
    target_mywalkfs.fs.map_file_fh("/path/to/directory/file",  BytesIO(b"test string"))

    results = list(target_mywalkfs.mywalkfs())
    assert results[0].type == "Directory"
    assert results[1].type == "Directory"
    assert results[2].type == "Directory"
    assert results[3].type == "Directory"

def test_layered_filesystem(target_mywalkfs: Target) -> None:
    layered_fs = LayerFilesystem()
    layer_1 = layered_fs.append_layer()
    layer_1.map_file_fh("/file_in_layer_1", BytesIO(b"test string"))
    layer_2 = layered_fs.append_layer()
    layer_2.map_file_fh("/file_in_layer_2", BytesIO(b"test string"))
    target_mywalkfs.fs.mount("/layered", layered_fs)

    results = list(target_mywalkfs.mywalkfs())

    assert results[3].fs_types == ["virtual", "virtual", "virtual"]
    assert len(results[3].volume_identifiers) == 3
