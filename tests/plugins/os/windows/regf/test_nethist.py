from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.regf.nethist import NethistPlugin

if TYPE_CHECKING:
    from dissect.target.helpers.regutil import VirtualHive
    from dissect.target.target import Target


def test_network_history_missing_profile(target_win: Target, hive_hklm: VirtualHive) -> None:
    """Skip signatures that reference a missing network profile."""
    signatures = VirtualKey(hive_hklm, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Signatures")
    unmanaged = VirtualKey(hive_hklm, "unmanaged")
    sig = VirtualKey(hive_hklm, "sig-1")
    sig.add_value("ProfileGuid", VirtualValue(hive_hklm, "ProfileGuid", "missing-profile-guid"))
    sig.add_value("Description", VirtualValue(hive_hklm, "Description", "Example network"))
    sig.add_value("DnsSuffix", VirtualValue(hive_hklm, "DnsSuffix", "example.local"))
    sig.add_value("FirstNetwork", VirtualValue(hive_hklm, "FirstNetwork", "ExampleNetwork"))
    sig.add_value("DefaultGatewayMac", VirtualValue(hive_hklm, "DefaultGatewayMac", b"\x00" * 6))
    unmanaged.add_subkey("sig-1", sig)
    signatures.add_subkey("unmanaged", unmanaged)
    hive_hklm.map_key(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Signatures",
        signatures,
    )

    profiles = VirtualKey(hive_hklm, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Profiles")
    hive_hklm.map_key("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Profiles", profiles)

    target_win.add_plugin(NethistPlugin)
    assert list(target_win.network_history()) == []
