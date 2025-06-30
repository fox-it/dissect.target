from __future__ import annotations

from collections.abc import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

ProductKeyRecord = TargetRecordDescriptor(
    "windows/registry/productkey",
    [
        ("string", "authorized_containers"),
        ("string", "backup_product_key_default"),
        ("string", "cache_store"),
        ("string", "token_store"),
        ("string", "type"),
    ],
)


class ProductKeyPlugin(Plugin):
    """Windows product key plugin."""

    # Should be Windows 11 and earlier
    KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform"

    def check_compatible(self) -> None:
        if not len(list(self.target.registry.keys(self.KEY))) > 0:
            raise UnsupportedPluginError("No SoftwareProtectionPlatform registry keys found")

    @export(record=ProductKeyRecord)
    def productkey(self) -> Iterator[ProductKeyRecord]:
        """Return the currently activated product key.

        The ``HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform`` registry
        key contains information about the product key that is used to activate Windows.

        References:
            - https://www.avg.com/en/signal/find-windows-10-product-key
        """
        for reg in self.target.registry.keys(self.KEY):
            values = {value.name: value.value for value in reg.values()}

            yield ProductKeyRecord(
                authorized_containers=values.get("AuthorizedContainers"),
                backup_product_key_default=values.get("BackupProductKeyDefault"),
                cache_store=values.get("CacheStore"),
                token_store=values.get("TokenStore"),
                type=values.get("Type"),
                _target=self.target,
            )
