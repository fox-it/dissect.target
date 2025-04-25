from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.linux.proc import ProcPlugin
from dissect.target.plugins.os.unix.linux.sockets import NetSocketPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_sockets_plugin(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem) -> None:
    target_linux_users.add_plugin(ProcPlugin)
    target_linux_users.add_plugin(NetSocketPlugin)
    results = list(target_linux_users.sockets())
    assert len(results) == 24


def test_tcp(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem) -> None:
    target_linux_users.add_plugin(ProcPlugin)
    target_linux_users.add_plugin(NetSocketPlugin)

    results = list(target_linux_users.sockets.tcp())

    assert len(results) == 7
    assert results[0].local_ip == "0.0.0.0"
    assert results[0].local_port == 22
    assert results[0].remote_ip == "0.0.0.0"
    assert results[0].remote_port == 0

    assert results[2].local_ip == "127.0.0.1"
    assert results[2].local_port == 631
    assert results[2].remote_ip == "0.0.0.0"
    assert results[2].remote_port == 0

    assert results[3].local_ip == "172.16.64.136"
    assert results[3].local_port == 22
    assert results[3].remote_ip == "172.16.64.1"
    assert results[3].remote_port == 49442

    assert results[4].local_ip == "::"
    assert results[4].local_port == 22
    assert results[4].remote_ip == "::"
    assert results[4].remote_port == 0

    assert results[6].local_ip == "::1"
    assert results[6].local_port == 631
    assert results[6].remote_ip == "::"
    assert results[6].remote_port == 0

    for result in results:
        assert result.protocol in ("tcp", "tcp6")
        assert result.owner == "root"
        assert result.pid in (0, 1, 2, 1337)
        assert result.inode in (1337, 1338, 0)
        assert result.cmdline in ("", None, "acquire -p full --proc", "test cmdline")


def test_udp(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem) -> None:
    target_linux_users.add_plugin(ProcPlugin)
    target_linux_users.add_plugin(NetSocketPlugin)
    results = list(target_linux_users.sockets.udp())

    assert len(results) == 7
    assert results[0].local_ip == "172.16.64.136"
    assert results[0].local_port == 68
    assert results[0].remote_ip == "172.16.64.254"
    assert results[0].remote_port == 67

    assert results[2].local_ip == "0.0.0.0"
    assert results[2].local_port == 58569
    assert results[2].remote_ip == "0.0.0.0"
    assert results[2].remote_port == 0

    assert results[3].local_ip == "0.0.0.0"
    assert results[3].local_port == 5353
    assert results[3].remote_ip == "0.0.0.0"
    assert results[3].remote_port == 0

    assert results[4].local_ip == "::"
    assert results[4].local_port == 59613
    assert results[4].remote_ip == "::"
    assert results[4].remote_port == 0

    for result in results:
        assert result.protocol in ("udp", "udp6")
        assert result.owner in ("root", "110")
        assert result.pid in (0, 1, 2, 3, 1337)
        assert result.inode in (1337, 1338, 1339, 0)
        assert result.cmdline in ("", None, "acquire -p full --proc", "sshd", "test cmdline")


def test_raw(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem) -> None:
    target_linux_users.add_plugin(ProcPlugin)
    target_linux_users.add_plugin(NetSocketPlugin)
    results = list(target_linux_users.sockets.raw())

    assert len(results) == 4
    assert results[0].local_ip == "0.0.0.0"
    assert results[0].local_port == 253
    assert results[0].remote_ip == "0.0.0.0"
    assert results[0].remote_port == 0

    assert results[1].local_ip == "0.0.0.0"
    assert results[1].local_port == 253
    assert results[1].remote_ip == "0.0.0.0"
    assert results[1].remote_port == 0

    for result in results:
        assert result.protocol in ("raw", "raw6")
        assert result.owner == "root"
        assert result.pid in (1, 1337)
        assert result.inode == (1337)
        assert result.cmdline in ("acquire -p full --proc", "test cmdline")


def test_packet(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem) -> None:
    target_linux_users.add_plugin(ProcPlugin)
    target_linux_users.add_plugin(NetSocketPlugin)
    results = list(target_linux_users.sockets.packet())

    assert len(results) == 2

    for result in results:
        assert result.ref == 3
        assert result.type == 3  # ETH_P_ALL
        assert result.protocol_type == "ETH_P_ALL"
        assert result.protocol == "packet"
        assert result.cmdline in ("acquire -p full --proc", "test cmdline")
        assert result.pid in (1, 1337)
        assert result.owner == "root"


def test_unix(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem) -> None:
    target_linux_users.add_plugin(ProcPlugin)
    target_linux_users.add_plugin(NetSocketPlugin)
    results = list(target_linux_users.sockets.unix())

    assert len(results) == 4
    for result in results:
        assert result.ref in (2, 3)
        assert result.protocol == "unix"
        assert result.type == "STREAM"
        assert result.state in ("LISTENING", "CONNECTED")
        assert result.flags in ("00010000", "00000000")

        assert result.path in (
            "/run/systemd/private",
            None,
            "/run/systemd/io.system.ManagedOOM",
            "@/tmp/dbus-YLq1FHVh",
        )
