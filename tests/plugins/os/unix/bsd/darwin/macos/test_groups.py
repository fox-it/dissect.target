from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.groups import GroupPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_files",
    [
        ["nobody.plist", "_eligibilityd.plist", "_applepay.plist"],
    ],
)
def test_groups(test_files: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    stat_results = []
    entries = []
    for test_file in test_files:
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/groups/{test_file}")
        fs_unix.map_file(f"/var/db/dslocal/nodes/Default/groups/{test_file}", data_file)
        entry = fs_unix.get(f"/var/db/dslocal/nodes/Default/groups/{test_file}")
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199
        entries.append(entry)
        stat_results.append(stat_result)

    with (
        patch.object(entries[0], "stat", return_value=stat_results[0]),
        patch.object(entries[1], "stat", return_value=stat_results[1]),
        patch.object(entries[2], "stat", return_value=stat_results[2]),
    ):
        target_unix.add_plugin(GroupPlugin)

        results = list(target_unix.groups())
        results.sort(key=lambda r: r.realname)
        assert len(results) == 3

        assert results[0].generateduid == "ABCDEFAB-CDEF-ABCD-EFAB-CDEFFFFFFFFE"
        assert results[0].members is None
        assert results[0].smb_sid == "S-1-0-0"
        assert results[0].gid == -2
        assert results[0].name == "['nobody', 'BUILTIN\\\\Nobody']"
        assert results[0].realname == "Nobody"
        assert results[0].source == "/var/db/dslocal/nodes/Default/groups/nobody.plist"

        assert results[-1].generateduid == "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000104"
        assert results[-1].members is None
        assert results[-1].smb_sid is None
        assert results[-1].gid == 260
        assert results[-1].name == "_applepay"
        assert results[-1].realname == "applepay Daemon"
        assert results[-1].source == "/var/db/dslocal/nodes/Default/groups/_applepay.plist"

        assert results[1].generateduid == "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000129"
        assert results[1].members == "_eligibilityd"
        assert results[1].smb_sid is None
        assert results[1].gid == 297
        assert results[1].name == "_eligibilityd"
        assert results[1].realname == "OS Eligibility Daemon"
        assert results[1].source == "/var/db/dslocal/nodes/Default/groups/_eligibilityd.plist"
