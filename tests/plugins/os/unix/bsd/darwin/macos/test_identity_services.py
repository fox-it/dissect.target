from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.identity_services import IdentityServicesPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "ids.db",
    ],
)
def test_identity_services(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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

    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/{test_file}")
    fs_unix.map_file(f"Users/user/Library/IdentityServices/{test_file}", data_file)
    entry = fs_unix.get(f"Users/user/Library/IdentityServices/{test_file}")
    stat_result = entry.stat()
    stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(IdentityServicesPlugin)

        results = list(target_unix.identity_services())

        assert len(results) == 2

        assert results[0].table == "_SqliteDatabaseProperties"
        assert results[0].key == "_ClientVersion"
        assert results[0].value == "10027"
        assert results[0].source == "/Users/user/Library/IdentityServices/ids.db"

        assert results[1].table == "_SqliteDatabaseProperties"
        assert results[1].key == "InternalMigration"
        assert results[1].value == "100"
        assert results[1].source == "/Users/user/Library/IdentityServices/ids.db"
