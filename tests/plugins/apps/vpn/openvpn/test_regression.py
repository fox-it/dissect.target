"""Tests from previous OpenVPNPlugin implementation to ensure backwards compatibility."""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.apps.vpn.openvpn.client import OpenVPNClientPlugin
from dissect.target.plugins.apps.vpn.openvpn.server import OpenVPNServerPlugin
from dissect.target.plugins.apps.vpn.openvpn.util import OpenVPNParser
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("target", "fs", "map_path"),
    [
        (
            "target_win_users",
            "fs_win",
            "Program Files/OpenVPN/config/helper",
        ),
        (
            "target_win_users",
            "fs_win",
            "Users/John/OpenVPN/config/helper",
        ),
    ],
)
def test_config_client(target: str, fs: str, map_path: str, request: pytest.FixtureRequest) -> None:
    """Test if we can parse OpenVPN client connection profile files as before."""

    target: Target = request.getfixturevalue(target)
    fs: Filesystem = request.getfixturevalue(fs)

    fs.map_file(f"{map_path}/client.ovpn", absolute_path("_data/plugins/apps/vpn/openvpn/regression/client.conf"))
    target.add_plugin(OpenVPNClientPlugin)

    record = next(target.openvpn.client.profiles())
    assert record.remote == [
        "my-server-1 1194",
        "my-server-2 1194",
        "my-server-3 1195",
        "my-server-4 11912",
    ]
    assert record.proto == "udp"
    assert record.dev == "tun"
    assert record.ca == "ca.crt"
    assert record.cert == "client.crt"
    assert record.key == "client.key"
    assert record.tls_auth == "ta.key"
    assert record.status is None
    assert record.log is None


@pytest.mark.parametrize(
    ("target", "fs", "map_path"),
    [
        (
            "target_unix_users",
            "fs_unix",
            "etc/openvpn",
        ),
    ],
)
def test_config_server(target: str, fs: str, map_path: str, request: pytest.FixtureRequest) -> None:
    """Test if we can parse OpenVPN server configuration files as before."""

    target: Target = request.getfixturevalue(target)
    fs: Filesystem = request.getfixturevalue(fs)

    fs.map_file(f"{map_path}/server.conf", absolute_path("_data/plugins/apps/vpn/openvpn/regression/server.conf"))
    target.add_plugin(OpenVPNServerPlugin)

    record = next(target.openvpn.server.config())

    assert record.local == "0.0.0.0"
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
    assert "BEGIN CERTIFICATE" in record.ca
    assert "BEGIN CERTIFICATE" in record.cert
    assert record.key is None
    assert record.tls_auth == "/etc/a ta.key"
    assert record.status == "/var/log/openvpn/openvpn-status.log"
    assert record.log is None


@pytest.mark.parametrize(
    ("data_string", "expected_data"),
    [
        (
            "<connection>\nroute data\n</connection>\n",
            {"connection": {"list_item0": {"route": "data"}}},
        ),
        (
            "<ca>\n----- BEGIN PRIVATE DATA -----\n</ca>",
            {
                "ca": "----- BEGIN PRIVATE DATA -----\n",
            },
        ),
    ],
)
def test_parser(data_string: str, expected_data: dict | list) -> None:
    parser = OpenVPNParser()
    parser.parse_file(io.StringIO(data_string))

    assert parser.parsed_data == expected_data
