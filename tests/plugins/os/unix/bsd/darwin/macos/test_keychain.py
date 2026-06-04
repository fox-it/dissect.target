from __future__ import annotations

from datetime import datetime, timezone
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
        assert results[0].cdat == datetime(2026, 3, 25, 14, 11, 26, 182470, tzinfo=timezone.utc)
        assert results[0].mdat == datetime(2026, 3, 25, 14, 11, 26, 182470, tzinfo=timezone.utc)
        assert results[0].desc is None
        assert results[0].icmt is None
        assert results[0].crtr is None
        assert results[0].keychain_type is None
        assert results[0].scrp is None
        assert results[0].labl is None
        assert results[0].alis is None
        assert results[0].invi is None
        assert results[0].nega is None
        assert results[0].cusi is None
        assert results[0].prot is None
        assert results[0].acct == b"T\xccQt\xcfq\x04qd\xc4\xd1\x94\xb9^\xc6S\x95\xa1\xc5\xdd"
        assert results[0].svce == b"\x84f\xd7\x7f7Qw)\x16>\x8c>}\x38\\z\xa7\tQ\x04"
        assert results[0].gena is None
        assert results[0].data is not None
        assert results[0].agrp == "com.apple.security.indirect-unlock-key"
        assert results[0].pdmn == "ak"
        assert results[0].sync == 0
        assert results[0].tomb == 0
        assert (
            results[0].sha1
            == "\udc9b\udce4|7],\udc88\udcfc\udcfa\udce7\x05\udcfe\udcb0\udcf2<\udce6\udca2\udcf2`\udc99"
        )
        assert results[0].vwht == ""
        assert results[0].tkid == ""
        assert results[0].musr == ""
        assert results[0].UUID == "FB64E7EF-96A7-4797-9883-E084735D7AC1"
        assert results[0].sysb is None
        assert results[0].pcss is None
        assert results[0].pcsk is None
        assert results[0].pcsi is None
        assert results[0].persistref == b"\x9c\xf0v\x86\xd2\x93E\x1b\xb4G8\xa0V\xfc\xfd\xf5"
        assert results[0].clip == 0
        assert results[0].ggrp == ""
        assert results[0].source == "/Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/keychain-2.db"

        assert results[84].table == "sqlite_sequence"
        assert results[84].name == "tversion"
        assert results[84].seq == 1
        assert results[84].source == "/Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/keychain-2.db"

        assert results[88].table == "inet"
        assert results[88].row_id == 1
        assert results[88].cdat == datetime(2026, 3, 25, 14, 11, 26, 218230, tzinfo=timezone.utc)
        assert results[88].mdat == datetime(2026, 3, 25, 14, 11, 26, 218230, tzinfo=timezone.utc)
        assert results[88].desc == b"-\x9c\xd9\x85\x03\x1cG\x93\x81\x8e\xd6\xc9\xc6n\x91\xb7\xf9\x0b \xf6"
        assert results[88].icmt is None
        assert results[88].crtr is None
        assert results[88].keychain_type is None
        assert results[88].scrp is None
        assert results[88].labl is None
        assert results[88].alis is None
        assert results[88].invi == 1
        assert results[88].nega is None
        assert results[88].cusi is None
        assert results[88].prot is None
        assert results[88].acct == b"\xd1*:s\x143|\xe6\x15nz\xe6\x06\xce\x1bs@\xe2\x87\x01"
        assert results[88].sdmn == b"\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t"
        assert results[88].srvr == b"\xd1*:s\x143|\xe6\x15nz\xe6\x06\xce\x1bs@\xe2\x87\x01"
        assert results[88].ptcl == "0"
        assert results[88].atyp == b"\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t"
        assert results[88].port == 0
        assert results[88].path_binary == b"\xec\xa4\xb9~\x03\x05\r\x96\x7fzl\xc4\xe0\xbb)\xbb\xaeV,\xa3"
        assert results[88].data is not None
        assert results[88].agrp == "com.apple.security.octagon"
        assert results[88].pdmn == "cku"
        assert results[88].sync == 0
        assert results[88].tomb == 0
        assert results[88].sha1 == "\udc8bB\x1dn\udcb4B\udcf9*\udcfdJ\udcc5\udcee\udce6ؤQ\udcae\udc97\udcbf\udcc2"
        assert results[88].vwht == ""
        assert results[88].tkid == ""
        assert results[88].musr == ""
        assert results[88].UUID == "7A4DAD90-B283-47BC-9AE4-1D237C3493D8"
        assert results[88].sysb == 1
        assert results[88].pcss is None
        assert results[88].pcsk is None
        assert results[88].pcsi is None
        assert results[88].persistref == b"TZ\x99|\xfd\xd2H\xd2\xad\xf3\x04L\xb3\xfcq\x9e"
        assert results[88].clip == 0
        assert results[88].ggrp == ""
        assert results[88].source == "/Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/keychain-2.db"

        assert results[89].table == "keys"
        assert results[89].row_id == 1
        assert results[89].cdat == datetime(2026, 3, 25, 14, 11, 27, 254737, tzinfo=timezone.utc)
        assert results[89].mdat == datetime(2026, 3, 25, 14, 11, 27, 254737, tzinfo=timezone.utc)
        assert results[89].kcls == b"\x90i\xcax\xe7E\n(QsC\x1b>R\xc5\xc2R\x99\xe4s"
        assert results[89].labl is None
        assert results[89].alis is None
        assert results[89].perm is None
        assert results[89].priv is None
        assert results[89].modi is None
        assert results[89].klbl == b"com.apple.routined.security.database"
        assert results[89].atag == b"\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t"
        assert results[89].crtr == 0
        assert results[89].keychain_type == 0
        assert results[89].bsiz == 0
        assert results[89].esiz == 0
        assert results[89].sdat == 0.0
        assert results[89].edat == 0.0
        assert results[89].sens is None
        assert results[89].asen is None
        assert results[89].extr is None
        assert results[89].next is None
        assert results[89].encr is None
        assert results[89].decr is None
        assert results[89].drve is None
        assert results[89].sign is None
        assert results[89].vrfy is None
        assert results[89].snrc is None
        assert results[89].vyrc is None
        assert results[89].wrap is None
        assert results[89].unwp is None
        assert results[89].data is not None
        assert results[89].agrp == "com.apple.routined"
        assert results[89].pdmn == "ck"
        assert results[89].sync == 1
        assert results[89].tomb == 0
        assert results[89].sha1 == "\udc9cc\udc98\udcd8\udcea0\udcb12bFL\udca4ot87\udcc7\udcf4\x7f\udc82"
        assert results[89].vwht == ""
        assert results[89].tkid == ""
        assert results[89].musr == ""
        assert results[89].UUID == "22A9A2ED-79C9-4665-80F5-021793509144"
        assert results[89].sysb is None
        assert results[89].pcss is None
        assert results[89].pcsk is None
        assert results[89].pcsi is None
        assert results[89].persistref == b"\xaf\x1e\xaaxqDG\xae\x81\xdb\xb1\xce\x9c\xe9C\xb9"
        assert results[89].clip == 0
        assert results[89].ggrp == ""
        assert results[89].source == "/Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/keychain-2.db"

        assert results[94].table == "tversion"
        assert results[94].row_id == 1
        assert results[94].version == "12"
        assert results[94].minor == 12
        assert results[94].source == "/Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/keychain-2.db"

        assert results[95].table == "metadatakeys"
        assert results[95].keyclass == 6
        assert results[95].actual_keyclass == 6
        assert (
            results[95].data
            == "r\udcccߨ\udcfdeѽi\udcb5\x16\udcd5+\udcf7\udcfa\udca0\udce4\udce7\x13+\udc9d\udc8b\udcae\x06g\udcb4\udc9b\udca1ѡ\udca2\udca1aY摳K\udc83\udc80"  # noqa E501
        )
        assert results[95].source == "/Users/user/Library/Keychains/E253F552-3A40-5010-9ACE-98662C9CFE20/keychain-2.db"
