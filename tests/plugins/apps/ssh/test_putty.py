from datetime import datetime, timezone
from os import stat

from flow.record.fieldtypes import path

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.apps.ssh.putty import PuTTYPlugin
from tests._utils import absolute_path


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
            "0x12812d95024c0d8683879fd38f977e9caa7e733334f75965bc50eba6e872e70a,0x2a564844fb9b6beb5e0491cefd9d03fe3af8caf03467c6c5fb9fe2bf78db2575",  # noqa E501
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

    assert records[0].ts == datetime.utcfromtimestamp(
        stat(absolute_path("_data/plugins/apps/ssh/putty/sessions/example-saved-session")).st_mtime
    ).replace(tzinfo=timezone.utc)
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
