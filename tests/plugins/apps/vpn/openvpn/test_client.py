from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.plugins.apps.vpn.openvpn.client import OpenVPNClientPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_logs(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we can parse OpenVPN client logs."""

    fs_win.map_file(
        "Users/John/OpenVPN/name-profile.log", absolute_path("_data/plugins/apps/vpn/openvpn/client/name-profile.log")
    )
    target_win_users.add_plugin(OpenVPNClientPlugin)
    records = list(target_win_users.openvpn.client.logs())

    assert records[0].ts == datetime(2025, 10, 20, 11, 20, 13, tzinfo=timezone.utc)
    assert (
        records[0].message == "Note: --cipher is not set. OpenVPN versions before 2.5 defaulted to BF-CBC as fallback "
        "when cipher negotiation failed in this case. If you need this fallback please add "
        "'--data-ciphers-fallback BF-CBC' to your configuration and/or add BF-CBC to --data-ciphers."
    )
    assert records[0].source == "C:\\Users\\John\\OpenVPN\\name-profile.log"

    assert records[1].ts == datetime(2025, 10, 20, 11, 20, 13, tzinfo=timezone.utc)
    assert (
        records[1].message == "OpenVPN 2.6.15 [git:v2.6.15/90bdd59a95170169] "
        "Windows [SSL (OpenSSL)] [LZO] [LZ4] [PKCS11] [AEAD] [DCO] built on Sep 22 2025"
    )
    assert records[1].source == "C:\\Users\\John\\OpenVPN\\name-profile.log"

    assert records[2].ts == datetime(2025, 10, 20, 11, 20, 13, tzinfo=timezone.utc)
    assert records[2].message == "Windows version 10.0 (Windows 10 or greater), amd64 executable"
    assert records[2].source == "C:\\Users\\John\\OpenVPN\\name-profile.log"


def test_profiles(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we can find and parse OpenVPN client connection profile files (*.ovpn)."""

    fs_win.map_file(
        "Users/John/OpenVPN/client.ovpn", absolute_path("_data/plugins/apps/vpn/openvpn/client/client.ovpn")
    )
    target_win_users.add_plugin(OpenVPNClientPlugin)
    records = list(target_win_users.openvpn.client.profiles())

    assert records[0].proto == "udp"
    assert records[0].dev == "tun"
    assert records[0].ca == (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBeTCB/6ADAgECAgRo5QC9MAoGCCqGSM49BAMCMBUxEzARBgNVBAMMCk9wZW5W\n"
        "UE4gQ0EwHhcNMjUxMDA2MjE1OTU3WhcNMzUxMDA1MjE1OTU3WjAVMRMwEQYDVQQD\n"
        "DApPcGVuVlBOIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEH6+NsCoi7mllD7hV\n"
        "egK88M/hy0kmQD7Jgh5IsO7IX5KIMTb679ltfBZwWJLJ6hMcs4hG/OgP77RrH+Bn\n"
        "73z7giio9XcDe7iqHB5YrW4I7aIiCfULIfGLSzvOWG8vG9L/oyAwHjAPBgNVHRMB\n"
        "Af8EBTADAQH/MAsGA1UdDwQEAwIBBjAKBggqhkjOPQQDAgNpADBmAjEApgTC7OSs\n"
        "IlDx9GKY05zsSwh0AGPsWdL9QL3eZx1kQQZYJmPGAgKSV2GTI+YH2c/bAjEAw1qD\n"
        "09jj90+YuLMmLyDl+Z+UBHra619/byZK8GddkhJnfOVnAE3F17OKg9ZGFrVq\n"
        "-----END CERTIFICATE-----\n"
    )
    assert records[0].cert == "client.crt"
    assert records[0].key == "client.key"
    assert records[0].auth is None
    assert records[0].status is None
    assert records[0].log is None
    assert records[0].verb == "3"
    assert records[0].tls_auth == "ta.key"
    assert records[0].source == "C:\\Users\\John\\OpenVPN\\client.ovpn"

    assert records[1].fingerprint.md5 == "cb38a3ebff4c16736434ea8df0244ae4"
    assert records[1].fingerprint.sha1 == "daf2bf53ba3a3b9080115ec39111f71f40cd8484"
    assert records[1].fingerprint.sha256 == "91b022ea3af6bcfc58b5123d2d9f990ec388f6746bf692003d4caf9a05c69687"
    assert records[1].issuer_dn == "CN=OpenVPN CA"
    assert records[1].not_valid_before == datetime(2025, 10, 6, 21, 59, 57, tzinfo=timezone.utc)
    assert records[1].not_valid_after == datetime(2035, 10, 5, 21, 59, 57, tzinfo=timezone.utc)
    assert records[1].subject_dn == "CN=OpenVPN CA"
    assert records[1].pem
    assert records[1].source == "C:\\Users\\John\\OpenVPN\\client.ovpn"


def test_config(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we can parse OpenVPN Connect client configuration json files."""

    fs_win.map_file(
        "Users/John/appdata/roaming/openvpn connect/config.json",
        absolute_path("_data/plugins/apps/vpn/openvpn/client/config.json"),
    )
    target_win_users.add_plugin(OpenVPNClientPlugin)
    records = list(target_win_users.openvpn.client.config())

    # proxy
    assert records[0].proxy_id == "proxy_1759841383472_7"
    assert records[0].display_name == "Access Server - Linux"
    assert records[0].host == "192.168.173.130"
    assert records[0].port == 1194
    assert records[0].username == "openvpn"
    assert records[0].password == "1XQtc2heauTD"
    assert records[0].source == "C:\\Users\\John\\AppData\\Roaming\\OpenVPN Connect\\config.json"

    # profiles
    assert records[1].profile_id == "1759841467737"
    assert records[1].display_name == "openvpn@192.168.173.130 [profile-userlocked]"
    assert records[1].host == "192.168.173.130"
    assert records[1].file_path == "C:\\Users\\test\\Downloads\\profile-userlocked.ovpn"
    assert records[1].last_connected == datetime(2025, 10, 7, 12, 51, 16, tzinfo=timezone.utc)
    assert records[1].saved_password == "False"
    assert records[1].private_key_password == "False"
    assert records[1].source == "C:\\Users\\John\\AppData\\Roaming\\OpenVPN Connect\\config.json"

    assert records[2].profile_id == "1760949762439"
    assert records[2].display_name == "192.168.173.130 [openvpn-client]"
    assert records[2].host == "192.168.173.130"
    assert records[2].file_path == "C:\\Users\\test\\Downloads\\openvpn-client.ovpn"
    assert records[2].last_connected == datetime(2025, 10, 20, 14, 34, 26, tzinfo=timezone.utc)
    assert records[2].saved_password == "False"
    assert records[2].private_key_password == "False"
    assert records[2].source == "C:\\Users\\John\\AppData\\Roaming\\OpenVPN Connect\\config.json"
