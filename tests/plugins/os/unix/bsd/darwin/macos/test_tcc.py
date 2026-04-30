from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.tcc import TCCPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            (
                "user.db",
                "system.db",
            ),
            (
                "/Users/user/Library/Application Support/com.apple.TCC/TCC.db",
                "/Library/Application Support/com.apple.TCC/TCC.db",
            ),
        ),
    ],
)
def test_tcc(
    names: tuple[str, ...],
    paths: tuple[str, ...],
    target_unix: Target,
    fs_unix: VirtualFilesystem,
) -> None:
    tz = timezone.utc

    user = UnixUserRecord(
        name="user",
        uid=501,
        gid=20,
        home="/Users/user",
        shell="/bin/zsh",
    )
    target_unix.users = lambda: [
        user,
    ]

    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/tcc/{name}")
        fs_unix.map_file(path, data_file)
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(TCCPlugin)

        results = list(target_unix.tcc())
        results.sort(key=lambda r: r.source)

        assert len(results) == 51

        assert results[0].table == "admin"
        assert results[0].key == "version"
        assert results[0].value == "32"
        assert results[0].source == "/Library/Application Support/com.apple.TCC/TCC.db"

        assert results[-2].table == "access"
        assert results[-2].service == "kTCCServiceLiverpool"
        assert results[-2].client == "com.apple.homeenergyd"
        assert results[-2].client_type == 0
        assert results[-2].auth_value == 2
        assert results[-2].auth_reason == 4
        assert results[-2].auth_version == 1
        assert results[-2].csreq is None
        assert results[-2].policy_id is None
        assert results[-2].indirect_object_identifier_type == "0"
        assert results[-2].indirect_object_identifier == "UNUSED"
        assert results[-2].indirect_object_code_identity is None
        assert results[-2].indirect_object_identifier_type == "0"
        assert results[-2].flags == 0
        assert results[-2].last_modified == datetime(2026, 3, 25, 14, 25, 29, tzinfo=tz)
        assert results[-2].pid is None
        assert results[-2].pid_version is None
        assert results[-2].boot_uuid == "UNUSED"
        assert results[-2].last_reminded == datetime(2026, 3, 25, 14, 25, 29, tzinfo=tz)
        assert results[-2].source == "/Users/user/Library/Application Support/com.apple.TCC/TCC.db"

        assert results[-1].table == "integrity_flag"
        assert results[-1].key == "integrity_flag"
        assert results[-1].value == "0"
        assert results[-1].source == "/Users/user/Library/Application Support/com.apple.TCC/TCC.db"
