from dissect.target.plugins.apps.vpns.wireguard import WireGuardPlugin

from ._utils import absolute_path


def test_wireguard_plugin_global_log(target_unix_users, fs_unix):
    wireguard_config_file = absolute_path("data/vpns/wireguard/wg0.conf")
    fs_unix.map_file("etc/wireguard/wg0.conf", wireguard_config_file)

    target_unix_users.add_plugin(WireGuardPlugin)
    records = list(target_unix_users.wireguard.config())
    assert len(records) == 6

    # Interface
    record = records[0]
    assert record.name == "wg0"
    assert str(record.address) == "10.13.37.1"
    assert record.private_key == "UHJpdmF0ZUtleQ=="
    assert record.listen_port == "12345"
    assert record.source == "etc/wireguard/wg0.conf"
    assert record.dns is None

    # Peer
    record = records[1]
    assert record.name is None
    assert str(record.allowed_ips) == "10.13.37.2/32"
    assert record.public_key == "UHVibGljS2V5MQ=="
    assert record.source == "etc/wireguard/wg0.conf"
