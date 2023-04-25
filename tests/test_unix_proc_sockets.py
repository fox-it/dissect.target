from io import BytesIO
from textwrap import dedent

from dissect.target.filesystem import VirtualSymlink
from dissect.target.plugins.os.unix.proc import ProcPlugin


def setup_procfs(fs_unix):
    procs = (
        ("proc/1", VirtualSymlink(fs_unix, "/proc/1/fd/4", "socket:[1337]"), "test\x00cmdline\x00"),
        ("proc/2", VirtualSymlink(fs_unix, "/proc/2/fd/4", "socket:[1338]"), "\x00"),
        ("proc/3", VirtualSymlink(fs_unix, "/proc/3/fd/4", "socket:[1339]"), "sshd"),
        (
            "proc/1337",
            VirtualSymlink(fs_unix, "/proc/1337/fd/4", "socket:[1337]"),
            "acquire\x00-p\x00full\x00--proc\x00",
        ),
    )
    stat_files_data = (
        "1 (systemd) S 0 1 1 0 -1 4194560 53787 457726 166 4255 112 260 761 548 20 0 1 0 30 184877056 2658 18446744073709551615 93937510957056 93937511789581 140726499200496 0 0 0 671173123 4096 1260 0 0 0 17 0 0 0 11 0 0 93937512175824 93937512476912 93937519890432 140726499204941 140726499204952 140726499204952 140726499205101 0\n",  # noqa
        "2 (kthread) K 1 1 1 0 -1 4194560 53787 457726 166 4255 112 260 761 548 20 0 1 0 30 184877056 2658 18446744073709551615 93937510957056 93937511789581 140726499200496 0 0 0 671173123 4096 1260 0 0 0 17 0 0 0 11 0 0 93937512175824 93937512476912 93937519890432 140726499204941 140726499204952 140726499204952 140726499205101 0\n",  # noqa
        "3 (sshd) W 1 2 1 0 -1 4194560 53787 457726 166 4255 112 260 761 548 20 0 1 0 30 184877056 2658 18446744073709551615 93937510957056 93937511789581 140726499200496 0 0 0 671173123 4096 1260 0 0 0 17 0 0 0 11 0 0 93937512175824 93937512476912 93937519890432 140726499204941 140726499204952 140726499204952 140726499205101 0\n",  # noqa
        "1337 (acquire) R 3 1 1 0 -1 4194560 53787 457726 166 4255 112 260 761 548 20 0 1 0 30 184877056 2658 18446744073709551615 93937510957056 93937511789581 140726499200496 0 0 0 671173123 4096 1260 0 0 0 17 0 0 0 11 0 0 93937512175824 93937512476912 93937519890432 140726499204941 140726499204952 140726499204952 140726499205101 0\n",  # noqa
    )

    for idx, proc in enumerate(procs):
        dir, fd, cmdline = proc
        fs_unix.makedirs(dir)
        fs_unix.map_file_entry(fd.path, fd)

        fs_unix.map_file_fh(dir + "/stat", BytesIO(stat_files_data[idx].encode()))
        fs_unix.map_file_fh(dir + "/cmdline", BytesIO(cmdline.encode()))

    # symlink acquire process to self
    fs_unix.link("/proc/1337", "/proc/self")

    # boottime and uptime are needed for for time tests
    fs_unix.map_file_fh("/proc/uptime", BytesIO(b"134368.27 132695.52\n"))
    fs_unix.map_file_fh("/proc/stat", BytesIO(b"btime 1680559854"))


def test_tcp(target_unix_users, fs_unix):
    tcp_socket_data = """sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1337 1 000000000e5941ba 100 0 0 10 0
1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1338 1 000000008b915f09 100 0 0 10 0
2: 884010AC:0016 014010AC:C122 01 00000000:00000000 02:00010C92 00000000     0        0 0
"""  # noqa

    setup_procfs(fs_unix)

    fs_unix.map_file_fh("/proc/net/tcp", BytesIO(dedent(tcp_socket_data).encode()))

    target_unix_users.add_plugin(ProcPlugin)
    results = list(target_unix_users.proc.sockets.tcp())

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
        assert result.owner == "0"
        assert result.pid in (0, 2, 1337)
        assert result.inode in (1337, 1338, 0)
        assert result.cmdline in ("", None, "acquire -p full --proc")


def test_tcp6(target_unix_users, fs_unix):
    tcp6_socket_data = """sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n
0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1337 1 0000000085d2a181 100 0 0 10 0\n   
1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1338 1 00000000bb201f51 100 0 0 10 0\n
"""  # noqa

    setup_procfs(fs_unix)

    fs_unix.map_file_fh("/proc/net/tcp6", BytesIO(dedent(tcp6_socket_data).encode()))

    target_unix_users.add_plugin(ProcPlugin)
    results = list(target_unix_users.proc.sockets.tcp6())

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
        assert result.owner == "0"
        assert result.pid in (0, 2, 1337)
        assert result.inode in (1337, 1338, 0)
        assert result.cmdline in ("", None, "acquire -p full --proc")


def test_udp(target_unix_users, fs_unix):
    udp_socket_data = """sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n  
344: 884010AC:0044 FE4010AC:0043 01 00000000:00000000 00:00000000 00000000     0        0 1337 2 00000000c414b4d1 0\n  
477: 00000000:E4C9 00000000:0000 07 00000000:00000000 00:00000000 00000000   110        0 1338 2 000000009ce0849c 0\n  
509: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   110        0 1339 2 00000000388d9bb8 0\n  
"""  # noqa

    setup_procfs(fs_unix)
    fs_unix.map_file_fh("/proc/net/udp", BytesIO(dedent(udp_socket_data).encode()))
    target_unix_users.add_plugin(ProcPlugin)
    results = list(target_unix_users.proc.sockets.udp())

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
        assert result.owner in ("0", "110")
        assert result.pid in (0, 2, 3, 1337)
        assert result.inode in (1337, 1338, 1339, 0)
        assert result.cmdline in ("", None, "acquire -p full --proc", "sshd")


def test_udp6(target_unix_users, fs_unix):
    udp6_socket_data = """sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n  
497: 00000000000000000000000000000000:E8DD 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   110        0 1337 2 00000000bb422355 0\n
509: 00000000000000000000000000000000:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   110        0 1338 2 000000005c20ab36 0\n
"""  # noqa

    setup_procfs(fs_unix)
    fs_unix.map_file_fh("/proc/net/udp6", BytesIO(dedent(udp6_socket_data).encode()))
    target_unix_users.add_plugin(ProcPlugin)
    results = list(target_unix_users.proc.sockets.udp6())

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


def test_raw(target_unix_users, fs_unix):
    raw_socket_data = """sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n
253: 00000000:00FD 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1337 2 00000000f7e50cca 0\n
"""  # noqa

    setup_procfs(fs_unix)
    fs_unix.map_file_fh("/proc/net/raw", BytesIO(dedent(raw_socket_data).encode()))
    target_unix_users.add_plugin(ProcPlugin)
    results = list(target_unix_users.proc.sockets.raw())

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
        assert result.owner == "0"
        assert result.pid in (1, 1337)
        assert result.inode == (1337)
        assert result.cmdline == "acquire -p full --proc"


def test_raw6(target_unix_users, fs_unix):
    raw6_socket_data = """sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n   
58: 00000000000000000000000000000000:003A 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1337 2 00000000fa98d32c 0\n
"""  # noqa

    setup_procfs(fs_unix)
    fs_unix.map_file_fh("/proc/net/raw6", BytesIO(dedent(raw6_socket_data).encode()))
    target_unix_users.add_plugin(ProcPlugin)
    results = list(target_unix_users.proc.sockets.raw6())

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
        assert result.owner == "0"
        assert result.pid in (1, 1337)
        assert result.inode == (1337)
        assert result.cmdline == "acquire -p full --proc"


def test_packet(target_unix_users, fs_unix):
    packet_socket_data = """sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n
00000000819f8865 3      3    0003   2     1 0      0      1337\n
"""
    setup_procfs(fs_unix)
    fs_unix.map_file_fh("/proc/net/packet", BytesIO(dedent(packet_socket_data).encode()))
    target_unix_users.add_plugin(ProcPlugin)
    results = list(target_unix_users.proc.sockets.packet())

    assert len(results) == 2

    for result in results:
        assert result.ref == 3
        assert result.type == 3  # ETH_P_ALL
        assert result.protocol_type == "ETH_P_ALL"
        assert result.protocol_string == "packet"
        assert result.cmdline == "acquire -p full --proc"
        assert result.pid == 1337
        assert result.owner == "0"


def test_unix(target_unix_users, fs_unix):
    unix_socket_data = """Num       RefCount Protocol Flags    Type St Inode Path\n
00000000a6061ba5: 00000002 00000000 00010000 0001 01 1337 /run/systemd/private\n
0000000065bb3d75: 00000003 00000000 00000000 0001 03 1338\n
000000008d0bfa50: 00000002 00000000 00010000 0001 01 1339 /run/systemd/io.system.ManagedOOM\n
00000000fb54422c: 00000002 00000000 00010000 0001 01 0 @/tmp/dbus-YLq1FHVh\n
"""

    setup_procfs(fs_unix)
    fs_unix.map_file_fh("/proc/net/unix", BytesIO(dedent(unix_socket_data).encode()))
    target_unix_users.add_plugin(ProcPlugin)
    results = list(target_unix_users.proc.sockets.unix())

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

        assert result.path in ("/run/systemd/private", None, "/run/systemd/io.system.ManagedOOM", "@/tmp/dbus-YLq1FHVh")
