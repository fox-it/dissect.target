from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest
from flow.record.fieldtypes import path

from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.apps.ssh.putty import PuTTYPlugin, construct_public_key
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_putty_plugin_ssh_host_keys_unix(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    ssh_host_keys = absolute_path("_data/plugins/apps/ssh/putty/sshhostkeys")
    fs_unix.map_file("/root/.putty/sshhostkeys", ssh_host_keys)

    target_unix_users.add_plugin(PuTTYPlugin)
    records = list(target_unix_users.putty.known_hosts())

    assert len(records) == 3

    assert records[0].mtime_ts is not None
    assert records[0].host == "192.168.123.130"
    assert records[0].port == 22

    assert records[0].key_type == "ssh-ed25519"
    assert records[0].public_key == "AAAAC3NzaC1lZDI1NTE5AAAAIHUl23i/4p/7xcZnNPDK+Dr+A539zpEEXutrm/tESFYq"
    assert records[0].fingerprint.md5 == "16da68cfc0e1b7954c84147a385be2b6"
    assert records[0].fingerprint.sha1 == "11e647366ef9b74feb55da7f8507a7180123eed0"
    assert records[0].fingerprint.sha256 == "0ecaca9db7d166fd55f84ad775074bd6c743ae2d26e6dac10e60e88efbfcc01d"

    assert records[0].path == path.from_posix("/root/.putty/sshhostkeys")
    assert records[0].username == "root"

    assert records[1].mtime_ts is not None
    assert records[1].host == "example.com"
    assert records[1].port == 22

    assert records[1].key_type == "ecdsa-sha2-nistp256"
    assert (
        records[1].public_key
        == "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNhJOmUcnvcVIizc67M3bS0/2Gz43YPHYCRaogqAgHvgVUartyfsl5nZBoFR3FiUc9kTJJUPybWbqXaGLEthjfM="  # noqa E501
    )
    assert records[1].fingerprint.md5 == "e23736ef80f12b672cf217c390a1acfb"
    assert records[1].fingerprint.sha1 == "93a03a809a02091aab194b04c836c37298c0602a"
    assert records[1].fingerprint.sha256 == "53d7097c310ce329d554dfb533c81f81d955facae8f46e9d7cfa4db58304c674"

    assert records[1].path == path.from_posix("/root/.putty/sshhostkeys")
    assert records[1].username == "root"

    assert records[2].mtime_ts is not None
    assert records[2].host == "1.2.3.4"
    assert records[2].port == 1234

    assert records[2].key_type == "rsa2"
    assert (
        records[2].public_key
        == "AAAAB3NzaC1yc2EAAAADAQABAAABgQCmYvCKueiA3lyhZuW0OAObOZvf0g957H0wGhGi3BruZSDpa9UQhsVNtgPZfuyx/yYWUIhQ4VSz+qw00IhZJt9myRNrXCxIABM/qubTghrdjRU+ydb0J9uTBIRz+ys/0dr0dg2Gc7C5w9+E3EpRit6VCZfTi8mNYZi+/GC12VYIDsqY9/4D4xloHJP+fs1mCNnY12VtJuIWw281fKaTCxm3H95NOBbAE6sAwr8H5lMLU34D4DcA5ZIG5F48yDmYUkILtN4qLAZMl4ZlQ6KpcxMYCN6DPj2NwR8JHzr+mkwjmGqbs8tjYD/KRYL2sYhK6Fdx7wvw5djQeVTEnhjxoeiCYNFAGkzB9BfeP4N0K2rp6F3NktFU4WIc6nLsX5G1LEWuAvAxwg+v6y4YzmpXHP+WrRHKyhS+B64aLpmD7AAJzPwSyqtt5+8SY3z7EMCpYBGz8uhdYzaY0U+qWFHtIfI5GLrl2akYBzH9t/YPAF6wdTuSh4jxVe2IVrd1x7g23Zs="  # noqa E501
    )
    assert records[2].fingerprint.md5 == "539539a9dec6afa0c8d9cdbb9357ed5e"
    assert records[2].fingerprint.sha1 == "c0f0c0a51ed7ae4c2b271f0426554f837f9508d0"
    assert records[2].fingerprint.sha256 == "c2d4bd813cdf1eec38ea8c7bbf0c56b129f9db3e78627d5b7ebfae8db60c5eb6"

    assert records[2].path == path.from_posix("/root/.putty/sshhostkeys")
    assert records[2].username == "root"


def test_putty_plugin_ssh_host_keys_windows(
    target_win_users: Target, fs_win: VirtualFilesystem, hive_hku: VirtualHive
) -> None:
    key_name = "Software\\SimonTatham\\PuTTY\\SshHostKeys"
    key = VirtualKey(hive_hku, key_name)
    key.add_value(
        "ssh-ed25519@22:192.168.123.130",
        VirtualValue(
            hive_hku,
            "ssh-ed25519@22:192.168.123.130",
            "0x12812d95024c0d8683879fd38f977e9caa7e733334f75965bc50eba6e872e70a,0x2a564844fb9b6beb5e0491cefd9d03fe3af8caf03467c6c5fb9fe2bf78db2575",
        ),
    )
    hive_hku.map_key(key_name, key)
    target_win_users.add_plugin(PuTTYPlugin)

    records = list(target_win_users.putty.known_hosts())

    assert len(records) == 1

    assert records[0].host == "192.168.123.130"
    assert records[0].port == 22
    assert records[0].key_type == "ssh-ed25519"
    assert records[0].public_key == "AAAAC3NzaC1lZDI1NTE5AAAAIHUl23i/4p/7xcZnNPDK+Dr+A539zpEEXutrm/tESFYq"
    assert records[0].path == path.from_windows("Software\\SimonTatham\\PuTTY\\SshHostKeys")


def test_putty_plugin_saved_sessions_unix(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    sessions_folder = absolute_path("_data/plugins/apps/ssh/putty/sessions")
    fs_unix.map_dir("/root/.putty/sessions", sessions_folder)

    target_unix_users.add_plugin(PuTTYPlugin)
    records = list(target_unix_users.putty.sessions())

    assert len(records) == 1

    assert records[0].ts == datetime.fromtimestamp(
        absolute_path("_data/plugins/apps/ssh/putty/sessions/example-saved-session").stat().st_mtime,
        tz=timezone.utc,
    )
    assert records[0].session_name == "example-saved-session"
    assert records[0].protocol == "ssh"
    assert records[0].host == "192.168.123.130"
    assert records[0].user == "saveduser"
    assert records[0].port == 22
    assert records[0].remote_command == ""
    assert records[0].port_forward == ""
    assert records[0].manual_ssh_host_keys == ""
    assert records[0].path == path.from_posix("/root/.putty/sessions/example-saved-session")
    assert records[0].username == "root"


def test_putty_plugin_saved_sessions_windows(
    target_win_users: Target, fs_win: VirtualFilesystem, hive_hku: VirtualHive
) -> None:
    key_name = "Software\\SimonTatham\\PuTTY\\Sessions\\example-saved-session"
    key = VirtualKey(hive_hku, key_name)
    key.add_value("HostName", VirtualValue(hive_hku, "HostName", "example.com"))
    key.add_value("UserName", VirtualValue(hive_hku, "UserName", "user"))
    key.add_value("Protocol", VirtualValue(hive_hku, "Protocol", "ssh"))
    key.add_value("PortNumber", VirtualValue(hive_hku, "PortNumber", 22))
    key.add_value("RemoteCommand", VirtualValue(hive_hku, "RemoteCommand", ""))
    key.add_value("PortForwardings", VirtualValue(hive_hku, "PortForwardings", ""))
    key.add_value("SSHManualHostKeys", VirtualValue(hive_hku, "SSHManualHostKeys", ""))
    hive_hku.map_key(key_name, key)
    target_win_users.add_plugin(PuTTYPlugin)

    records = list(target_win_users.putty.sessions())

    assert len(records) == 1

    assert records[0].session_name == "example-saved-session"
    assert records[0].protocol == "ssh"
    assert records[0].host == "example.com"
    assert records[0].user == "user"
    assert records[0].port == 22
    assert records[0].remote_command == ""
    assert records[0].port_forward == ""
    assert records[0].manual_ssh_host_keys == ""
    assert records[0].path == path.from_windows("Software\\SimonTatham\\PuTTY\\Sessions\\example-saved-session")


def test_construct_public_key() -> None:
    with pytest.raises(TypeError, match="Invalid key_type or iv"):
        construct_public_key(None, None)

    assert construct_public_key("unsupported", "some-iv") == (
        "some-iv",
        (None, None, None),
    )
