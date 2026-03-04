from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.plugins.apps.vpn.openvpn.openvpn import OpenVPNPlugin
from dissect.target.plugins.apps.vpn.openvpn.server import OpenVPNServerPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_logs(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse regular OpenVPN server log files."""

    fs_unix.map_file("var/log/openvpn.log", absolute_path("_data/plugins/apps/vpn/openvpn/server/openvpn.log"))
    target_unix.add_plugin(OpenVPNServerPlugin)
    records = list(target_unix.openvpn.server.logs())

    assert records[0].ts == datetime(2025, 10, 21, 00, 34, 24, tzinfo=timezone.utc)
    assert (
        records[0].message
        == "OpenVPN 2.6.14 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]"
    )
    assert records[0].source == "/var/log/openvpn.log"

    assert records[1].ts == datetime(2025, 10, 21, 00, 34, 25, tzinfo=timezone.utc)
    assert records[1].message == "Initialization Sequence Completed"
    assert records[1].source == "/var/log/openvpn.log"

    assert records[2].ts == datetime(2025, 10, 21, 00, 34, 25, tzinfo=timezone.utc)
    assert (
        records[2].message
        == "192.168.173.129:64259 [openvpn-client] Peer Connection Initiated with [AF_INET]192.168.173.129:64259"
    )
    assert records[2].source == "/var/log/openvpn.log"


def test_config(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse OpenVPN server configuration files."""

    fs_unix.map_file("etc/openvpn/server.conf", absolute_path("_data/plugins/apps/vpn/openvpn/server/server.conf"))
    target_unix.add_plugin(OpenVPNServerPlugin)
    records = list(target_unix.openvpn.server.config(export_key=True))

    assert records[0].ts
    assert records[0].port == 1194
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
    assert records[0].cert == (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBnjCCASSgAwIBAgIHVzbVWySnYDAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApP\n"
        "cGVuVlBOIENBMB4XDTI1MTAwNjIyNDMzNloXDTM1MTAwNTIyNDMzNlowEjEQMA4G\n"
        "A1UEAwwHb3BlbnZwbjB2MBAGByqGSM49AgEGBSuBBAAiA2IABL5XINW+VxgT86u6\n"
        "cFWDTUik4+2XNyfLxpvMQwvShcJC5M3ns5Up45cQHHGIAiAZH7Mr2fA6oj5ub8s5\n"
        "F4LKDujUzjp3b4yokP6Sw/34/A+sb3Asjqx7z54lhW2vH8vl1qNFMEMwDAYDVR0T\n"
        "AQH/BAIwADALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwEQYJYIZI\n"
        "AYb4QgEBBAQDAgeAMAoGCCqGSM49BAMCA2gAMGUCMQCr/b8W9ydlmS9h8Exv1UR9\n"
        "Ae0jSNSjzSQ06p8uITDxkzCQ+sIiYRi0bi8UZLgG8zoCMFD/Or9tgP3bhdfFsruM\n"
        "95DAhxXiA5cfLpDXc9OpDSnyFFvjKpcyZ7Zwqh+zvxEcXA==\n"
        "-----END CERTIFICATE-----\n"
    )
    assert records[0].key == (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDtsxwuIQmB8gaB+SvU\n"
        "XAidYBbRT3J6nbqpnY899nzbrbdLhDN9XvngHjohEyyv8+ehZANiAAS+VyDVvlcY\n"
        "E/OrunBVg01IpOPtlzcny8abzEML0oXCQuTN57OVKeOXEBxxiAIgGR+zK9nwOqI+\n"
        "bm/LOReCyg7o1M46d2+MqJD+ksP9+PwPrG9wLI6se8+eJYVtrx/L5dY=\n"
        "-----END PRIVATE KEY-----\n"
    )
    assert records[0].dh == "dh2048.pem"
    assert records[0].server == "10.8.0.0 255.255.255.0"
    assert records[0].ifconfig_pool_persist == "/var/log/openvpn/ipp.txt"
    assert records[0].pushed_options == [
        "route 192.168.10.0 255.255.255.0",
        "route 192.168.20.0 255.255.255.0",
        "route 192.168.30.0 255.255.255.0",
    ]
    assert not records[0].client_to_client
    assert not records[0].duplicate_cn
    assert records[0].status == "/var/log/openvpn/openvpn-status.log"
    assert records[0].verb == "3"
    assert records[0].tls_auth == "/etc/a ta.key"
    assert records[0].source == "/etc/openvpn/server.conf"

    assert records[1].ts == datetime(2025, 10, 6, 21, 59, 57, tzinfo=timezone.utc)
    assert records[1].fingerprint.sha1 == "daf2bf53ba3a3b9080115ec39111f71f40cd8484"
    assert records[1].serial_number == 1759838397
    assert records[1].serial_number_hex == "68e500bd"
    assert records[1].not_valid_before == datetime(2025, 10, 6, 21, 59, 57, tzinfo=timezone.utc)
    assert records[1].not_valid_after == datetime(2035, 10, 5, 21, 59, 57, tzinfo=timezone.utc)
    assert records[1].issuer_dn == "CN=OpenVPN CA"
    assert records[1].subject_dn == "CN=OpenVPN CA"
    assert records[1].pem
    assert records[1].source == "/etc/openvpn/server.conf"

    assert records[2].fingerprint.md5 == "21f078a3b8443ce1521ae1e9daf92ead"
    assert records[2].fingerprint.sha1 == "d49e69953e4743b64dc17779c5ac909ee0da20cf"
    assert records[2].fingerprint.sha256 == "4100214673511d2ff2593a87865beaaa8d3a551e937c8564b97494c7c404934b"
    assert records[2].hostname == "localhost"
    assert records[2].issuer_dn == "CN=OpenVPN CA"
    assert records[2].not_valid_before == datetime(2025, 10, 6, 22, 43, 36, tzinfo=timezone.utc)
    assert records[2].not_valid_after == datetime(2035, 10, 5, 22, 43, 36, tzinfo=timezone.utc)
    assert records[2].subject_dn == "CN=openvpn"
    assert records[2].pem
    assert records[2].source == "/etc/openvpn/server.conf"


def test_users(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse OpenVPN AS Server configured users."""

    fs_unix.map_file(
        "usr/local/openvpn_as/etc/db/userprop.db", absolute_path("_data/plugins/apps/vpn/openvpn/server/userprop.db")
    )

    target_unix.add_plugin(OpenVPNServerPlugin)
    records = list(target_unix.openvpn.server.users())

    assert records[0].user_id == "1"
    assert records[0].user_name == "__DEFAULT__"
    assert records[0].user_type == "user_default"
    assert not records[0].is_superuser
    assert records[0].password_digest is None
    assert records[0].user_auth_type is None
    assert records[0].source == "/usr/local/openvpn_as/etc/db/userprop.db"

    assert records[1].user_id == "2"
    assert records[1].user_name == "openvpn"
    assert records[1].user_type == "user_compile"
    assert records[1].is_superuser
    assert records[1].password_digest == "$P$+Azokv3BqzV/ogvLyP0qZA==$y5iPl61UtrrFs9xl2yUZkC2nxp4Qe68LsY2iZAROFQI="
    assert records[1].user_auth_type == "local"
    assert records[1].source == "/usr/local/openvpn_as/etc/db/userprop.db"


def test_openvpn_server_history_connection(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    openvpn_log_file = absolute_path("_data/plugins/apps/vpn/openvpn/server/openvpnas.node.log")
    openvpn_log_db_file = absolute_path("_data/plugins/apps/vpn/openvpn/server/log.db")

    fs_unix.map_file("var/log/openvpnas.node.log", openvpn_log_file)
    fs_unix.map_file("usr/local/openvpn_as/etc/db/log.db", openvpn_log_db_file)

    target_unix.add_plugin(OpenVPNServerPlugin)

    connection_records = list(target_unix.openvpn.server.connections())

    # Log file
    connection_record = connection_records[0]
    assert connection_record.ts == datetime(2025, 10, 9, 8, 29, 19, tzinfo=timezone.utc)
    assert connection_record.client_id == "2"
    assert connection_record.client_ip == "192.168.173.131"
    assert connection_record.client_port == 34193
    assert connection_record.client_proto == "8094"
    assert connection_record.client_version == "v3.11.5"
    assert connection_record.client_platform == "linux"
    assert connection_record.client_plat_rel is None
    assert connection_record.client_gui_ver == "OpenVPN3/Linux/v26"
    assert connection_record.client_ciphers == "AES-128-GCM:AES-192-GCM:AES-256-GCM:CHACHA20-POLY1305"
    assert connection_record.client_ssl == "OpenSSL_3.0.13_30_Jan_2024"
    assert connection_record.client_hwaddr == "e3fd6191e473c963af1810df1316b58b45a5918a6409b9e57561735d71d519dc"
    assert connection_record.source == "/var/log/openvpnas.node.log"

    # Log database
    db_record = connection_records[1]
    assert db_record.ts == datetime(2025, 10, 7, 13, 50, 0, 0, tzinfo=timezone.utc)
    assert db_record.client_id == "test-VM"
    assert db_record.client_username == "openvpn"
    assert db_record.client_ip == "192.168.173.129"
    assert db_record.client_port == 1194
    assert db_record.client_vpn_ip == ["172.27.232.2"]
    assert db_record.client_proto == "UDP"
    assert db_record.client_version == "3.11.3"
    assert db_record.client_gui_ver == "OCWindows_3.8.0-4528"
    assert db_record.client_platform == "win"
    assert db_record.client_conn_duration == 3526
    assert db_record.source == "/usr/local/openvpn_as/etc/db/log.db"

    db_record = connection_records[2]
    assert db_record.ts == datetime(2025, 10, 9, 9, 41, 53, 0, tzinfo=timezone.utc)
    assert db_record.client_id == "test-VM"
    assert db_record.client_username == "openvpn"
    assert db_record.client_ip == "192.168.173.131"
    assert db_record.client_port == 1194
    assert db_record.client_vpn_ip == ["172.27.232.2"]
    assert db_record.client_proto == "UDP"
    assert db_record.client_version == "v3.11.5"
    assert db_record.client_gui_ver == "OpenVPN3/Linux/v26"
    assert db_record.client_platform == "linux"
    assert db_record.client_conn_duration == 3388
    assert db_record.source == "/usr/local/openvpn_as/etc/db/log.db"


def test_openvpn_server_live_connection(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    openvpn_status_file = absolute_path("_data/plugins/apps/vpn/openvpn/server/status.log")
    openvpn_log_file = absolute_path("_data/plugins/apps/vpn/openvpn/server/openvpn.log")
    fs_unix.map_file("var/log/openvpn/status.log", openvpn_status_file)
    fs_unix.map_file("var/log/openvpn/openvpn-status.log", openvpn_status_file)
    fs_unix.map_file("var/log/openvpn.log", openvpn_log_file)

    target_unix.add_plugin(OpenVPNPlugin)
    target_unix.add_plugin(OpenVPNServerPlugin)
    status_records = list(target_unix.openvpn.server.connections())

    status_record = status_records[0]
    assert status_record.client_conn_since == datetime(2025, 10, 21, 00, 34, 25, tzinfo=timezone.utc)
    assert status_record.client_common_name == "openvpn-client"

    assert status_record.client_ip == "192.168.173.129"
    assert status_record.client_port == 64259
    assert status_record.client_vpn_ip == ["10.8.0.2"]
    assert status_record.client_username == "UNDEF"
    assert status_record.client_id == "0"
    assert status_record.peer_id == "0"
    assert status_record.bytes_received == 16284
    assert status_record.bytes_sent == 11160
    assert status_record.client_ciphers == "AES-256-GCM\n"
    assert status_record.source == "/var/log/openvpn/status.log"
