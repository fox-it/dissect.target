from __future__ import annotations

import stat
from typing import TYPE_CHECKING
from unittest.mock import Mock

from dissect.target.filesystem import VirtualFile, VirtualFilesystem
from dissect.target.helpers import fsutil
from dissect.target.plugins.filesystem.unix.suid import SuidPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_suid_plugin(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    vfile = VirtualFile(fs_unix, "binary", None)
    vfile.lstat = Mock()
    vfile.lstat.return_value = fsutil.stat_result([stat.S_IFREG | stat.S_ISUID, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    fs_unix.map_file_entry("/path/to/suid/binary", vfile)

    target_unix.add_plugin(SuidPlugin)

    results = list(target_unix.suid_binaries())
    assert len(results) == 1

    assert results[0].path == "/path/to/suid/binary"
