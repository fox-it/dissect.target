from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.regf.trusteddocs import TrustedDocumentsPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_trusteddocs_plugin(target_win_users: Target, hive_hku: VirtualHive) -> None:
    """Test if we detect and parse TrustedDocs entries.

    References:
        - https://github.com/Psmths/windows-forensic-artifacts/blob/main/file-activity/trustrecords-registry-key.md
    """
    trusteddocs_key_name = "Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents"
    trusteddocs_key = VirtualKey(hive_hku, trusteddocs_key_name)

    subkey_name = "TrustRecords"
    subkey = VirtualKey(hive_hku, subkey_name)
    subkey.add_value(
        "%USERPROFILE%\\Downloads\\example1.docm",
        VirtualValue(
            hive_hku,
            "%USERPROFILE%\\Downloads\\example1.docm",
            bytes.fromhex("5AAC70BDC995DA010028A153C5FFFFFFA9DEB30101000000"),
        ),
    )
    subkey.add_value(
        "%USERPROFILE%\\Downloads\\example2.docm",
        VirtualValue(
            hive_hku,
            "%USERPROFILE%\\Downloads\\example2.docm",
            bytes.fromhex("5AAC70BDC995DA010028A153C5FFFFFFABDEB301FFFFFF7F"),
        ),
    )

    trusteddocs_key.add_subkey(subkey_name, subkey)
    hive_hku.map_key(trusteddocs_key_name, trusteddocs_key)

    target_win_users.add_plugin(TrustedDocumentsPlugin)

    results = list(target_win_users.trusteddocs())

    assert len(results) == 2

    assert results[0].raw == bytes.fromhex("5AAC70BDC995DA010028A153C5FFFFFFA9DEB30101000000")
    assert results[0].application == "Word"
    assert (
        results[0].document == "%USERPROFILE%\\Downloads\\example1.docm"
    )  # Resolve does not work here, should be 'C:\\Users\\John'
    assert results[0].ts_created == datetime(2024, 4, 23, 22, 1, 6, 9405, tzinfo=timezone.utc)
    assert results[0].ts_enabled == datetime(
        2024, 4, 23, 22, 1, tzinfo=timezone.utc
    )  # Unfortunately only minute-precision here.
    assert results[0].state == "EDITING_ENABLED"

    assert results[1].raw == bytes.fromhex("5AAC70BDC995DA010028A153C5FFFFFFABDEB301FFFFFF7F")
    assert results[1].application == "Word"
    assert (
        results[1].document == "%USERPROFILE%\\Downloads\\example2.docm"
    )  # Resolve does not work here, should be 'C:\\Users\\John'
    assert results[1].ts_created == datetime(2024, 4, 23, 22, 1, 6, 9405, tzinfo=timezone.utc)
    assert results[1].ts_enabled == datetime(
        2024, 4, 23, 22, 3, tzinfo=timezone.utc
    )  # Unfortunately only minute-precision here.
    assert results[1].state == "MACROS_ENABLED"
