from __future__ import annotations

import io
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.apps.vpn.openvpn import (
    OpenVPNClient,
    OpenVPNParser,
    OpenVPNPlugin,
    OpenVPNServer,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


def map_openvpn_configs(filesystem: Filesystem, target_dir: Path) -> None:
    client_config = absolute_path("_data/plugins/apps/vpn/openvpn/client.conf")
    server_config = absolute_path("_data/plugins/apps/vpn/openvpn/server.conf")
    filesystem.map_file(str(target_dir.joinpath("server.conf")), server_config)
    filesystem.map_file(str(target_dir.joinpath("server.ovpn")), server_config)
    filesystem.map_file(str(target_dir.joinpath("client.conf")), client_config)
    filesystem.map_file(str(target_dir.joinpath("client.ovpn")), client_config)


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
        (
            "target_unix_users",
            "fs_unix",
            "etc/openvpn",
        ),
    ],
)
def test_openvpn_plugin(target: str, fs: str, map_path: str, request: pytest.FixtureRequest) -> None:
    target: Target = request.getfixturevalue(target)
    fs: Filesystem = request.getfixturevalue(fs)
    map_openvpn_configs(fs, fs.path(map_path))
    target.add_plugin(OpenVPNPlugin)
    records = list(target.openvpn.config())
    _verify_records(records)


def _verify_records(records: list[OpenVPNClient | OpenVPNServer]) -> None:
    assert len(records) == 4

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
            assert "BEGIN CERTIFICATE" in record.ca
            assert "BEGIN CERTIFICATE" in record.cert
            assert record.key is None
            assert record.redacted_key
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
            assert not record.redacted_key
            assert record.tls_auth == "ta.key"
            assert record.status is None
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
def test_openvpn_config(data_string: str, expected_data: dict | list) -> None:
    parser = OpenVPNParser()
    parser.parse_file(io.StringIO(data_string))

    assert parser.parsed_data == expected_data
