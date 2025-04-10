from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.apps.productivity.sevenzip import SevenZipPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_sevenzip_windows(target_win_users: Target, hive_hku: VirtualHive) -> None:
    """Test if we detect compression and extraction GUI dialog artifacts in 7-Zip."""

    # Compression dialog artifact
    key_path = "Software\\7-Zip\\Compression"
    key = VirtualKey(hive_hku, key_path)
    key.add_value(
        "ArcHistory",
        bytes.fromhex(
            "43003a005c00550073006500720073005c00410064006d0069006e006900730074007200610074006f007200"
            "5c0044006f00630075006d0065006e00740073005c006500780061006d0070006c0065002e0037007a000000"
        ),
    )
    key.timestamp = datetime(2025, 12, 31, 12, 34, 0, tzinfo=timezone.utc)
    hive_hku.map_key(key_path, key)

    # Extraction dialog artifact
    key_path = "Software\\7-Zip\\Extraction"
    key = VirtualKey(hive_hku, key_path)
    key.add_value(
        "PathHistory",
        bytes.fromhex(
            "43003a005c00550073006500720073005c00410064006d0069006e006900730074007200610074006f007200"
            "5c004400650073006b0074006f0070005c006500780061006d0070006c0065005c000000"
        ),
    )
    key.timestamp = datetime(2025, 12, 31, 13, 37, 0, tzinfo=timezone.utc)
    hive_hku.map_key(key_path, key)

    target_win_users.add_plugin(SevenZipPlugin)

    results = list(target_win_users.sevenzip())
    assert len(results) == 2

    assert results[0]._desc.name == "application/productivity/sevenzip/archistory"
    assert results[0].ts == datetime(2025, 12, 31, 12, 34, 0, tzinfo=timezone.utc)
    assert results[0].path == "C:\\Users\\Administrator\\Documents\\example.7z"

    assert results[1]._desc.name == "application/productivity/sevenzip/pathhistory"
    assert results[1].ts == datetime(2025, 12, 31, 13, 37, 0, tzinfo=timezone.utc)
    assert results[1].path == "C:\\Users\\Administrator\\Desktop\\example"
