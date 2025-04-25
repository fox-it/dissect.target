import gzip
from io import BytesIO

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.linux.fortios._os import FortiOSPlugin
from dissect.target.plugins.os.unix.linux.fortios.generic import GenericPlugin
from dissect.target.plugins.os.unix.linux.fortios.locale import FortiOSLocalePlugin
from dissect.target.target import Target


def test_fortigate_os(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we detect FortiGate OS correctly."""

    global_config = """\
    #config-version=FGVM64-7.4.2-FW-build2571-231219:opmode=0:vdom=0
    config system global
        set alias "FortiGate-VM64"
        set hostname "FortiGate-VM64"
        set timezone "US/Pacific"
    end
    config system admin
        edit "admin"
            set accprofile "super_admin"
            set vdom "root"
            set password ENC SH22zS4+QvU399DXuDApIVHu5fGh3wQCwO1aGeqlbA08G9tB/DvJsqLdG9HA18=
        next
    end
    config system dns
        set primary 96.45.45.45
        set secondary 96.45.46.46
    end
    """

    iface_config = """\
    edit "port1"
        set vdom "root"
        set ip 1.2.3.4 255.255.255.0
        set allowaccess https
        set type physical
        set snmp-index 1
    next
    """

    root_config = """\
    config user group
        edit "Guest-group"
            set member "guest"
        next
    end
    config user local
        edit "guest"
            set type password
            set passwd ENC pATZu+74jg21Ktwn9zMDS/bGcYumPFDZMnBKh+86851cd0Ig2CS1zbqQa7mpUGpCNfnDKlDkjobzwIlUbXkHgRYxBWWf99DtTvm7g7UsEBGnf8Xa06ZNd62b5Zb4MVfKQJ/uh5Ky0dI4RujLfv8PqrU7VVKKTAPUdzEtC5ehWZzUxRAFohNM6WhklTUpLV58M+zoRA==
        next
    end
    """  # noqa: E501

    fs_unix.map_file_fh("/.flatkc", BytesIO(b""))
    fs_unix.map_file_fh("/rootfs.gz", BytesIO(b""))
    fs_unix.map_file_fh("/data/config/sys_global.conf.gz", BytesIO(gzip.compress(global_config.encode())))
    fs_unix.map_file_fh("/data/config/global_system_interface.gz", BytesIO(gzip.compress(iface_config.encode())))
    fs_unix.map_file_fh("/data/config/sys_vd_root+root.conf.gz", BytesIO(gzip.compress(root_config.encode())))
    fs_unix.map_file_fh(
        "/bin/grep", BytesIO(bytes.fromhex("7f454c4602010100000000000000000002003e0001000000004b4000000000"))
    )

    target_unix.add_plugin(FortiOSPlugin)
    target_unix.add_plugin(FortiOSLocalePlugin)
    target_unix.add_plugin(GenericPlugin)

    # tests FortiOSPlugin.detect() indirectly
    assert target_unix.os == "fortios"

    target_unix._os_plugin = FortiOSPlugin
    target_unix.apply()

    assert target_unix.os == "fortios"
    assert target_unix.hostname == "FortiGate-VM64"
    assert target_unix.version == "FortiGate VM 7.4.2 (build 2571, 2023-12-19)"
    assert target_unix.ips == ["1.2.3.4"]
    assert target_unix.dns == ["96.45.45.45", "96.45.46.46"]
    assert target_unix.architecture == "x86_64-unix"
    assert target_unix.language == "en_US"
    assert target_unix.timezone == "US/Pacific"

    users = list(target_unix.users())
    assert len(users) == 2
    assert users[0].hostname == "FortiGate-VM64"
    assert users[0].name == "admin"
    assert users[0].groups == ["super_admin"]
    assert users[0].password == "ENC:SH22zS4+QvU399DXuDApIVHu5fGh3wQCwO1aGeqlbA08G9tB/DvJsqLdG9HA18="
    assert users[0].home == "/root"

    assert users[1].hostname == "FortiGate-VM64"
    assert users[1].name == "guest"
    assert users[1].groups == ["Guest-group"]
    assert users[1].password == "guest"
    assert users[1].home is None
