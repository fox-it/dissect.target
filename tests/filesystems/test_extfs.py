from unittest.mock import Mock, patch

import pytest
from dissect.extfs.c_ext import c_ext
from dissect.extfs.extfs import INode, _parse_ns_ts
from dissect.util.ts import from_unix_ns

from dissect.target.filesystems.extfs import ExtFilesystemEntry


def test_stat_information() -> None:
    extfs = Mock()
    extfs.sb.s_inode_size = 129

    entry = INode(extfs, 42)

    inode = c_ext.ext4_inode()
    inode.i_crtime = 20
    inode.i_crtime_extra = 20

    entry._inode = inode

    fs_entry = ExtFilesystemEntry(Mock(), "some/path", entry)

    stat_info = fs_entry.lstat()

    assert stat_info.st_ino == 42
    assert stat_info.st_nlink == 0
    assert stat_info.st_uid == 0
    assert stat_info.st_gid == 0

    assert stat_info.st_atime == 0
    assert stat_info.st_atime_ns == 0
    assert stat_info.st_mtime == 0
    assert stat_info.st_mtime_ns == 0
    assert stat_info.st_ctime == 0
    assert stat_info.st_ctime_ns == 0
    assert stat_info.st_birthtime == from_unix_ns(_parse_ns_ts(20, 20)).timestamp()
    assert stat_info.st_birthtime_ns == _parse_ns_ts(20, 20)
