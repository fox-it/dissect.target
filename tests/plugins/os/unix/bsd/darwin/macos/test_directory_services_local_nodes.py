from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.directory_services_local_nodes import (
    DirectoryServicesLocalNodesPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_files",
    [
        [
            "sqlindex",
            "sqlindex-wal",
        ]
    ],
)
def test_directory_services_local_nodes(test_files: list[str], target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    tz = timezone.utc
    for test_file in test_files:
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/directory_services_local_nodes/{test_file}")
        fs_unix.map_file(f"/var/db/dslocal/nodes/Default/{test_file}", data_file)
        entry = fs_unix.get(f"/var/db/dslocal/nodes/Default/{test_file}")
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(DirectoryServicesLocalNodesPlugin)

        results = list(target_unix.directory_services_local_nodes())

        assert len(results) == 1452

        results.sort(key=lambda r: r.tables)

        assert results[0].tables == ["generateduid", "rec:groups"]
        assert results[0].filetime == datetime(2026, 3, 20, 4, 25, 57, tzinfo=tz)
        assert results[0].filename == "_appowner.plist"
        assert results[0].recordtype == "groups"
        assert results[0].value == "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000057"
        assert results[0].source == "/var/db/dslocal/nodes/Default/sqlindex"

        assert results[-69].tables == ["users"]
        assert results[-69].filetime is None
        assert results[-69].filename == "_appserveradm.plist"
        assert results[-69].recordtype == "groups"
        assert results[-69].value == "_mbsetupuser"
        assert results[-69].source == "/var/db/dslocal/nodes/Default/sqlindex"
