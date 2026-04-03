from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.shadow import ShadowPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_files",
    [
        ["_mbsetupuser.plist", "user.plist"],
    ],
)
def test_passwords(test_files: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    for test_file in test_files:
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/shadow/{test_file}")
        fs_unix.map_file(f"/var/db/dslocal/nodes/Default/users/{test_file}", data_file)
        entry = fs_unix.get(f"/var/db/dslocal/nodes/Default/users/{test_file}")
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(ShadowPlugin)

        results = list(target_unix.passwords())
        results.sort(key=lambda r: r.name)
        assert len(results) == 2

        assert results[0].name == "_mbsetupuser"
        assert (
            results[0].hash
            == "46e8c10ca67d3d8a3998fa83b9dbb845d3a5c8b257d60272a22912a1a0fd6bff5d315b6f5b50577e465a8ae57f5a0f0fd52ea708d614141c428911d3273b67125d9599198590376ad38f43d6ed3a1173fd86c378b9879c5a026809c802df5ae5bd72e53bb033f9aa9e0e24600c03d0ec287e466f5c79eb1be42fac7afeee2b7e"  # noqa: E501
        )
        assert results[0].salt == "225ea6a940b08c6985c792a7195ef008527b5c83829ca0850bdcae77e517c9b5"
        assert results[0].iterations == 78125
        assert results[0].algorithm == "SALTED-SHA512-PBKDF2"
        assert results[0].source == "/var/db/dslocal/nodes/Default/users/_mbsetupuser.plist"

        assert results[-1].name == "user"
        assert (
            results[-1].hash
            == "f6e502079b9eb8b2f49b099c235aed2debb0b80084dca99f9a23db41dbfca88be0266bf62dfca5923ccd20d4c8f81140e2cb09b7951cce001ccb37b9fa3cee46b68a0edfc8e055e7f523feaec444f775eaddcf7d4e91e5e918a0dd715a4a749fd92974b023db4cb8851f4fdee3bd091755686be92a3f8ff906c6552907a8b0dc"  # noqa: E501
        )
        assert results[-1].salt == "64e7869eef2d9bf35bc9b72fddcf90055be833eed2c6c7d58ca91f0c0754f5f6"
        assert results[-1].iterations == 128205
        assert results[-1].algorithm == "SALTED-SHA512-PBKDF2"
        assert results[-1].source == "/var/db/dslocal/nodes/Default/users/user.plist"
