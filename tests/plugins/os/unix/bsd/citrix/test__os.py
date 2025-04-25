import textwrap
from io import BytesIO

from flow.record.fieldtypes import posix_path

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.bsd.citrix._os import CitrixPlugin
from dissect.target.target import Target


def test_citrix_os(target_citrix: Target, fs_bsd: VirtualFilesystem) -> None:
    example_etc_passwd = """
    # $FreeBSD: releng/11.4/etc/master.passwd 359448 2020-03-30 17:11:21Z brooks $
    #
    root:*:0:0:Charlie &:/root:/usr/bin/bash
    bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
    nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
    """

    fs_bsd.map_file_fh("/root/.cli_history", BytesIO(b'echo "hello world"'))
    fs_bsd.map_file_fh("/var/nstmp/robin/.cli_history", BytesIO(b'echo "hello world"'))
    fs_bsd.map_file_fh("/var/nstmp/alfred/.cli_history", BytesIO(b'echo "bye world"'))
    fs_bsd.map_file_fh("/etc/passwd", BytesIO(textwrap.dedent(example_etc_passwd).encode()))

    target_citrix.add_plugin(CitrixPlugin)

    assert target_citrix.os == "citrix-netscaler"
    hostname = target_citrix.hostname
    version = target_citrix.version
    users = sorted(target_citrix.users(), key=lambda user: (user.name, str(user.home) if user.home else ""))
    ips = target_citrix.ips
    ips.sort()

    assert hostname == "mynetscaler"
    assert version == "NetScaler 13.1 build 30 (ns-13.1-30.52)"

    assert ips == ["10.0.0.68", "10.0.0.69"]

    assert target_citrix.timezone == "Europe/Amsterdam"

    assert len(users) == 8

    assert users[0].name == "alfred"  # Only listed in /var/nstmp
    assert users[0].home == posix_path("/var/nstmp/alfred")

    assert users[1].name == "batman"  # Only listed in config
    assert users[1].home is None

    assert users[2].name == "bind"  # User entry from /etc/passwd, home overwritten from '/' to None
    assert users[2].home is None

    assert users[3].name == "jasontodd"  # Only listed in config backup
    assert users[3].home is None

    assert users[4].name == "nobody"  # User entry for the nobody user from /etc/passwd
    assert users[4].home == posix_path("/nonexistent")

    assert users[5].name == "robin"  # Listed in config and /var/nstmp
    assert users[5].home == posix_path("/var/nstmp/robin")

    assert users[6].name == "root"  # User entry for /root, from the config
    assert users[6].home == posix_path("/root")
    assert users[6].shell is None

    assert users[7].name == "root"  # User entry for /root, from /etc/passwd
    assert users[7].home == posix_path("/root")
    assert users[7].shell == "/usr/bin/bash"
