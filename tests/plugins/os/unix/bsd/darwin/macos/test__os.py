from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record.fieldtypes import posix_path

from dissect.target.plugin import OperatingSystem
from dissect.target.plugins.os.unix.bsd.darwin.macos._os import MacOSPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_unix_bsd_darwin_macos_os(target_macos_users: Target, fs_macos: VirtualFilesystem) -> None:
    """Test if we detect a macOS target correctly."""

    target_macos_users.add_plugin(MacOSPlugin)

    interface = absolute_path("_data/plugins/os/unix/bsd/darwin/macos/_os/en0.plist")
    fs_macos.map_file("/private/var/db/dhcpclient/leases/en0.plist", interface)

    users = list(target_macos_users.users())
    ips = target_macos_users.ips
    ips.sort()

    dissect_user = users[0]
    test_user = users[1]

    assert target_macos_users.os == OperatingSystem.MACOS
    assert target_macos_users.hostname == "dummys Mac"
    assert target_macos_users.version == "macOS 11.7.5 (20G1225)"

    assert len(users) == 2
    assert len(ips) == 2

    assert dissect_user._desc.name == "macos/user"
    assert dissect_user.name == "_dissect"
    assert dissect_user.passwd == "*"
    assert dissect_user.home == posix_path("/Users/dissect")
    assert dissect_user.shell == "/usr/bin/false"
    assert dissect_user.source == "/var/db/dslocal/nodes/Default/users/_dissect.plist"

    assert test_user.home is None

    assert ips == ["10.42.43.63", "10.42.43.64"]
