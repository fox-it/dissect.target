from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.apps.vpn.wireguard import WireGuardPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_wireguard_plugin_global_log(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    wireguard_config_file = absolute_path("_data/plugins/apps/vpn/wireguard/wg0.conf")
    fs_unix.map_file("/etc/wireguard/wg0.conf", wireguard_config_file)

    target_unix_users.add_plugin(WireGuardPlugin)
    records = list(target_unix_users.wireguard.config())
    assert len(records) == 6

    # Interface
    record = records[0]
    assert record.name == "wg0"
    assert str(record.address) == "10.13.37.1"
    assert record.private_key == "UHJpdmF0ZUtleQ=="
    assert record.listen_port == 12345
    assert record.source == "/etc/wireguard/wg0.conf"
    assert record.dns is None

    # Peer
    record = records[1]
    assert record.name is None
    assert [str(addr) for addr in record.allowed_ips] == ["10.13.37.2/32", "::/0"]
    assert record.public_key == "UHVibGljS2V5MQ=="
    assert record.source == "/etc/wireguard/wg0.conf"

    # Peer
    record = records[2]
    assert record.name is None
    assert [str(addr) for addr in record.allowed_ips] == ["10.13.37.3/32", "::/0"]
    assert record.public_key == "UHVibGljS2V5Mg=="
    assert record.source == "/etc/wireguard/wg0.conf"
