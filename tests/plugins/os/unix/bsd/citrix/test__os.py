from io import BytesIO

from dissect.target.plugins.os.unix.bsd.citrix._os import CitrixBsdPlugin


def test_unix_bsd_citrix_os(target_citrix):
    target_citrix.add_plugin(CitrixBsdPlugin)

    assert target_citrix.os == "citrix-netscaler"

    target_citrix.fs.mounts["/"].map_file_fh("/root/.cli_history", BytesIO(b'echo "hello world"'))
    target_citrix.fs.mounts["/"].map_file_fh("/var/nstmp/robin/.cli_history", BytesIO(b'echo "hello world"'))
    target_citrix.fs.mounts["/"].map_file_fh("/var/nstmp/alfred/.cli_history", BytesIO(b'echo "bye world"'))

    hostname = target_citrix.hostname
    version = target_citrix.version
    users = sorted(list(target_citrix.users()), key=lambda user: (user.name, user.home if user.home else ""))
    ips = target_citrix.ips
    ips.sort()

    assert hostname == "mynetscaler"
    assert version == "NetScaler 13.1 build 30 (ns-13.1-30.52)"

    assert ips == ["10.0.0.68", "10.0.0.69"]

    assert target_citrix.timezone == "Europe/Amsterdam"

    assert len(users) == 5

    assert users[0].name == "alfred"  # Only listed in /var/nstmp
    assert users[0].home == "/var/nstmp/alfred"

    assert users[1].name == "batman"  # Only listed in config
    assert users[1].home is None

    assert users[2].name == "jasontodd"  # Only listed in config backup
    assert users[2].home is None

    assert users[3].name == "robin"  # Listed in config and /var/nstmp
    assert users[3].home == "/var/nstmp/robin"

    assert users[4].name == "root"  # User entry for /root
    assert users[4].home == "/root"
