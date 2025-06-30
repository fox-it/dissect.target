from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows.regf.productkey import ProductKeyPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target

def test_productkey(target_win_users: Target, hive_hklm: VirtualHive) -> None:
    key_name = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform"
    key = VirtualKey(hive_hklm, key_name)
    key.add_value("AuthorizedContainers", "Container1, Container2")
    key.add_value("BackupProductKeyDefault", "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
    key.add_value("CacheStore", "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\Cache")
    key.add_value("TokenStore", "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows NT\\SoftwareProtectionPlatform")
    key.add_value("Type", "Retail")
    hive_hklm.map_key(key_name, key)

    target_win_users.add_plugin(ProductKeyPlugin)

    records = list(target_win_users.productkey())

    assert len(records) == 1
    record = records[0]

    assert record.authorized_containers == "Container1, Container2"
    assert record.backup_product_key_default == "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
    assert record.cache_store == "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\Cache"
    assert record.token_store == "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows NT\\SoftwareProtectionPlatform"
    assert record.type == "Retail"