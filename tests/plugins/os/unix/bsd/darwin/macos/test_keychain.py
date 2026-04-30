from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.keychain import KeychainPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "keychain-2.db",
    ],
)
def test_keychain(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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
    fs_unix.map_file(f"Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/{test_file}", data_file)
    entry = fs_unix.get(f"/Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/{test_file}")
    stat_result = entry.stat()
    stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(KeychainPlugin)

        results = list(target_unix.keychain())

        assert len(results) == 100

        assert results[0].table == "genp"
        assert results[0].row_id == 1
        assert results[0].agrp == "com.apple.security.indirect-unlock-key"
        assert results[0].pdmn == "ak"
        assert results[0].sync == 0
        assert results[0].tomb == 0
        assert results[0].clip == 0
        assert results[0].ggrp == ""
        assert results[0].source == "/Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/keychain-2.db"

        assert results[84].table == "sqlite_sequence"
        assert results[84].name == "tversion"
        assert results[84].seq == 1
        assert results[84].source == "/Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/keychain-2.db"

        assert results[88].table == "inet"
        assert results[88].row_id == 1
        assert results[88].invi == 1
        assert results[88].agrp == "com.apple.security.octagon"
        assert results[88].pdmn == "cku"
        assert results[88].sync == 0
        assert results[88].tomb == 0
        assert results[88].sysb == 1
        assert results[88].clip == 0
        assert results[88].ggrp == ""
        assert results[88].source == "/Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/keychain-2.db"

        assert results[89].table == "keys"
        assert results[89].row_id == 1
        assert results[89].crtr == "0"
        assert results[89].type == "0"
        assert results[89].agrp == "com.apple.routined"
        assert results[89].pdmn == "ck"
        assert results[89].sync == 1
        assert results[89].tomb == 0
        assert results[89].clip == 0
        assert results[89].ggrp == ""
        assert results[89].source == "/Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/keychain-2.db"

        assert results[94].table == "tversion"
        assert results[94].row_id == 1
        assert results[94].version == "12"
        assert results[94].minor == 12
        assert results[94].source == "/Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/keychain-2.db"

        assert results[95].table == "metadatakeys"
        assert results[95].keyclass == "6"
        assert results[95].actual_key_class == "6"
        assert results[95].data == (
            "r\udcccߨ\udcfdeѽi\udcb5\x16\udcd5+\udcf7\udcfa\udca0\udce4\udce7\x13+\udc9d\udc8b\udcae\x06g\udcb4\udc9b\udca1ѡ\udca2\udca1aY摳K\udc83\udc80"  # noqa RUF001
        )
        assert results[95].source == "/Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/keychain-2.db"
