from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.linux.proc import ProcPlugin
from dissect.target.target import Target


def test_sockets_plugin(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem):
    target_linux_users.add_plugin(ProcPlugin)
    results = list(target_linux_users.sockets())
    assert len(results) == 24


def test_tcp(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem):
    target_linux_users.add_plugin(ProcPlugin)
    results = list(target_linux_users.proc.sockets.tcp())

    assert len(results) == 4
    assert results[0].local_ip.exploded == "0.0.0.0"
    assert results[0].local_port == 22
    assert results[0].remote_ip.exploded == "0.0.0.0"
    assert results[0].remote_port == 0

    assert results[2].local_ip.exploded == "127.0.0.1"
    assert results[2].local_port == 631
    assert results[2].remote_ip.exploded == "0.0.0.0"
    assert results[2].remote_port == 0

    assert results[3].local_ip.exploded == "172.16.64.136"
    assert results[3].local_port == 22
    assert results[3].remote_ip.exploded == "172.16.64.1"
    assert results[3].remote_port == 49442

    for result in results:
        assert result.protocol_string == "tcp"
        assert result.owner == "root"
        assert result.pid in (0, 2, 1337)
        assert result.inode in (1337, 1338, 0)
        assert result.cmdline in ("", None, "acquire -p full --proc")


def test_tcp6(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem):
    target_linux_users.add_plugin(ProcPlugin)
    results = list(target_linux_users.proc.sockets.tcp6())

    assert len(results) == 3
    assert results[0].local_ip.exploded == "0000:0000:0000:0000:0000:0000:0000:0000"
    assert results[0].local_port == 22
    assert results[0].remote_ip.exploded == "0000:0000:0000:0000:0000:0000:0000:0000"
    assert results[0].remote_port == 0

    assert results[2].local_ip.exploded == "0000:0000:0000:0000:0000:0000:0000:0001"
    assert results[2].local_port == 631
    assert results[2].remote_ip.exploded == "0000:0000:0000:0000:0000:0000:0000:0000"
    assert results[2].remote_port == 0

    for result in results:
        assert result.protocol_string == "tcp6"
        assert result.owner == "root"
        assert result.pid in (0, 2, 1337)
        assert result.inode in (1337, 1338, 0)
        assert result.cmdline in ("", None, "acquire -p full --proc")


def test_udp(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem):
    target_linux_users.add_plugin(ProcPlugin)
    results = list(target_linux_users.proc.sockets.udp())

    assert len(results) == 4
    assert results[0].local_ip.exploded == "172.16.64.136"
    assert results[0].local_port == 68
    assert results[0].remote_ip.exploded == "172.16.64.254"
    assert results[0].remote_port == 67

    assert results[2].local_ip.exploded == "0.0.0.0"
    assert results[2].local_port == 58569
    assert results[2].remote_ip.exploded == "0.0.0.0"
    assert results[2].remote_port == 0

    assert results[3].local_ip.exploded == "0.0.0.0"
    assert results[3].local_port == 5353
    assert results[3].remote_ip.exploded == "0.0.0.0"
    assert results[3].remote_port == 0

    for result in results:
        assert result.protocol_string == "udp"
        assert result.owner in ("root", "110")
        assert result.pid in (0, 2, 3, 1337)
        assert result.inode in (1337, 1338, 1339, 0)
        assert result.cmdline in ("", None, "acquire -p full --proc", "sshd")


def test_udp6(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem):
    target_linux_users.add_plugin(ProcPlugin)
    results = list(target_linux_users.proc.sockets.udp6())

    assert len(results) == 3
    assert results[0].local_ip.exploded == "0000:0000:0000:0000:0000:0000:0000:0000"
    assert results[0].local_port == 59613
    assert results[0].remote_ip.exploded == "0000:0000:0000:0000:0000:0000:0000:0000"
    assert results[0].remote_port == 0

    assert results[2].local_ip.exploded == "0000:0000:0000:0000:0000:0000:0000:0000"
    assert results[2].local_port == 5353
    assert results[2].remote_ip.exploded == "0000:0000:0000:0000:0000:0000:0000:0000"
    assert results[2].remote_port == 0

    for result in results:
        assert result.protocol_string == "udp6"
        assert result.owner == "110"
        assert result.pid in (0, 2, 3, 1337)
        assert result.inode in (1337, 1338, 1339, 0)
        assert result.cmdline in ("", None, "acquire -p full --proc", "sshd")


def test_raw(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem):
    target_linux_users.add_plugin(ProcPlugin)
    results = list(target_linux_users.proc.sockets.raw())

    assert len(results) == 2
    assert results[0].local_ip.exploded == "0.0.0.0"
    assert results[0].local_port == 253
    assert results[0].remote_ip.exploded == "0.0.0.0"
    assert results[0].remote_port == 0

    assert results[1].local_ip.exploded == "0.0.0.0"
    assert results[1].local_port == 253
    assert results[1].remote_ip.exploded == "0.0.0.0"
    assert results[1].remote_port == 0

    for result in results:
        assert result.protocol_string == "raw"
        assert result.owner == "root"
        assert result.pid in (1, 1337)
        assert result.inode == (1337)
        assert result.cmdline == "acquire -p full --proc"


def test_raw6(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem):
    target_linux_users.add_plugin(ProcPlugin)
    results = list(target_linux_users.proc.sockets.raw6())

    assert len(results) == 2
    assert results[0].local_ip.exploded == "0000:0000:0000:0000:0000:0000:0000:0000"
    assert results[0].local_port == 58
    assert results[0].remote_ip.exploded == "0000:0000:0000:0000:0000:0000:0000:0000"
    assert results[0].remote_port == 0

    assert results[1].local_ip.exploded == "0000:0000:0000:0000:0000:0000:0000:0000"
    assert results[1].local_port == 58
    assert results[1].remote_ip.exploded == "0000:0000:0000:0000:0000:0000:0000:0000"
    assert results[1].remote_port == 0

    for result in results:
        assert result.protocol_string == "raw6"
        assert result.owner == "root"
        assert result.pid in (1, 1337)
        assert result.inode == (1337)
        assert result.cmdline == "acquire -p full --proc"


def test_packet(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem):
    target_linux_users.add_plugin(ProcPlugin)
    results = list(target_linux_users.proc.sockets.packet())

    assert len(results) == 2

    for result in results:
        assert result.ref == 3
        assert result.type == 3  # ETH_P_ALL
        assert result.protocol_type == "ETH_P_ALL"
        assert result.protocol_string == "packet"
        assert result.cmdline == "acquire -p full --proc"
        assert result.pid == 1337
        assert result.owner == "root"


def test_unix(target_linux_users: Target, fs_linux_proc_sockets: VirtualFilesystem):
    target_linux_users.add_plugin(ProcPlugin)
    results = list(target_linux_users.proc.sockets.unix())

    assert len(results) == 4
    for result in results:
        assert result.protocol_string == "unix"
        assert result.ref in (2, 3)
        assert result.protocol == 0
        assert result.type == 1
        assert result.state in (1, 3)
        assert result.flags in ("00010000", "00000000")
        assert result.state_string in ("CONNECTED", "LISTENING")
        assert result.stream_type_string == "STREAM"

        assert result.path in (
            "/run/systemd/private",
            None,
            "/run/systemd/io.system.ManagedOOM",
            "@/tmp/dbus-YLq1FHVh",
        )
