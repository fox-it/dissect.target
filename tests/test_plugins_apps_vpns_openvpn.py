from dissect.target.plugins.apps.vpns.openvpn import (
    OpenVPNPlugin,
    OpenVPNClient,
    OpenVPNServer,
)

from ._utils import absolute_path

from typing import Union


def test_openvpn_plugin_unix(target_unix_users, fs_unix):
    client_config = absolute_path("data/vpns/openvpn/client.conf")
    server_config = absolute_path("data/vpns/openvpn/server.conf")
    fs_unix.map_file("etc/openvpn/server.conf", server_config)
    fs_unix.map_file("etc/openvpn/client.conf", client_config)

    target_unix_users.add_plugin(OpenVPNPlugin)
    records = list(target_unix_users.openvpn.config())
    assert len(records) == 2
    _verify_records(records)


def test_openvpn_plugin_windows_system(target_win_users, fs_win):
    client_config = absolute_path("data/vpns/openvpn/client.conf")
    server_config = absolute_path("data/vpns/openvpn/server.conf")
    fs_win.map_file("Program Files/OpenVPN/config/server.conf", server_config)
    fs_win.map_file("Program Files/OpenVPN/config/client.conf", client_config)

    target_win_users.add_plugin(OpenVPNPlugin)
    records = list(target_win_users.openvpn.config())
    assert len(records) == 2
    _verify_records(records)


def test_openvpn_plugin_windows_users(target_win_users, fs_win):
    client_config = absolute_path("data/vpns/openvpn/client.conf")
    server_config = absolute_path("data/vpns/openvpn/server.conf")
    user = target_win_users.user_details.find(username="John")
    config_path = user.home_path.joinpath("OpenVPN/config/")

    # drop C:/
    fs_win.map_file(str(config_path.joinpath("server.conf"))[3:], server_config)
    fs_win.map_file(str(config_path.joinpath("client.conf"))[3:], client_config)

    target_win_users.add_plugin(OpenVPNPlugin)
    records = list(target_win_users.openvpn.config())
    assert len(records) == 2
    _verify_records(records)


def _verify_records(records: list[Union[OpenVPNClient, OpenVPNServer]]):
    # Server
    for record in records:
        if record.name == "server":
            assert record.name == "server"
            assert record.local.val.compressed == "0.0.0.0"
            assert record.port == 1194
            assert record.topology is None
            assert record.server == "10.8.0.0 255.255.255.0"
            assert record.ifconfig_pool_persist == "/var/log/openvpn/ipp.txt"
            assert record.pushed_options == [
                "route 192.168.10.0 255.255.255.0",
                "route 192.168.20.0 255.255.255.0",
                "route 192.168.30.0 255.255.255.0",
            ]
            assert record.client_to_client.value is False
            assert record.duplicate_cn.value is False
            assert record.proto == "udp"
            assert record.dev == "tun"
            assert record.ca == "ca.crt"
            assert record.cert == "server.crt"
            assert record.key == "server.key"
            assert record.tls_auth == "/etc/a ta.key"
            assert record.status == "/var/log/openvpn/openvpn-status.log"
            assert record.log is None
        else:
            # Client
            assert record.remote == [
                "my-server-1 1194",
                "my-server-2 1194",
                "my-server-3 1195",
                "my-server-4 11912",
            ]
            assert record.name == "client"
            assert record.proto == "udp"
            assert record.dev == "tun"
            assert record.ca == "ca.crt"
            assert record.cert == "client.crt"
            assert record.key == "client.key"
            assert record.tls_auth == "ta.key"
            assert record.status is None
            assert record.log is None
