import platform

import pytest

from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.regf.trusteddocs import TrustedDocumentsPlugin


@pytest.mark.skipif(platform.system() == "Windows", reason="Path comparison error. Needs to be fixed.")
def test_trusteddocs_plugin(target_win_users, hive_hku):
    trusteddocs_key_name = "Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents"
    trusteddocs_key = VirtualKey(hive_hku, trusteddocs_key_name)

    subkey_name = "TrustRecords"
    subkey = VirtualKey(hive_hku, subkey_name)
    subkey.add_value("c:\\Users\\John\\test", VirtualValue(hive_hku, "c:\\Users\\John\\test", b"test"))

    trusteddocs_key.add_subkey(subkey_name, subkey)
    hive_hku.map_key(trusteddocs_key_name, trusteddocs_key)

    target_win_users.add_plugin(TrustedDocumentsPlugin)

    results = list(target_win_users.trusteddocs())

    assert len(results) == 1

    result = results[0]

    assert result.value == b"test"
    assert result.application == "Word"
    assert str(result.document_path) == "c:/Users/John/test"
