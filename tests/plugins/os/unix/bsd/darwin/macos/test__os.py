from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import Mock

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugin import OperatingSystem
from dissect.target.plugins.os.unix.bsd.darwin.macos._os import MacOSPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_macos_os(target_macos_users: Target, fs_macos: VirtualFilesystem) -> None:
    """Test if we detect a macOS target correctly.

    Some test files originate from a logical test image of a MacBook Pro 2019 model.

    References:
        - https://cfreds.nist.gov/all/Hexordia/2026MVSCTFMac
    """
    target_macos_users.add_plugin(MacOSPlugin)

    assert target_macos_users.os == OperatingSystem.MACOS
    assert target_macos_users.hostname == "Alexs-MacBook-Pro"
    assert target_macos_users.ips == ["192.168.1.190"]
    assert target_macos_users.version == "macOS 15.4 (24E248)"
    assert target_macos_users.architecture == "x86_64-apple-macos"

    users = list(target_macos_users.users())
    assert len(users) == 3

    assert users[0].name == "root"
    assert users[0].passwd == "*"
    assert users[0].uid == 0
    assert users[0].gid == 0
    assert users[0].gecos == "System Administrator"
    assert users[0].home == "/var/root"
    assert users[0].shell == "/bin/sh"
    assert users[0].source == "/private/var/db/dslocal/nodes/Default/users/root.plist"

    assert users[1].name == "_dissect"
    assert users[1].passwd == "*"
    assert users[1].uid == 1337
    assert users[1].gid == 1337
    assert users[1].gecos == "Dissect"
    assert users[1].home == "/Users/dissect"
    assert users[1].shell == "/usr/bin/false"
    assert users[1].source == "/private/var/db/dslocal/nodes/Default/users/_dissect.plist"

    assert users[2].name == "alexmaurie"
    assert users[2].passwd == "********"
    assert users[2].uid == 501
    assert users[2].gid == 20
    assert users[2].gecos == "Alex Maurie"
    assert users[2].home == "/Users/alexmaurie"
    assert users[2].shell == "/bin/zsh"
    assert users[2].source == "/private/var/db/dslocal/nodes/Default/users/alexmaurie.plist"


def test_apfs_mounts(target_bare: Target) -> None:
    """Test that macOS firmlinks are correctly mounted."""
    mock_system_volume = VirtualFilesystem()
    mock_system_volume.__type__ = "apfs"
    mock_system_volume.apfs = Mock()
    mock_system_volume.apfs.role = Mock()
    mock_system_volume.apfs.role.name = "SYSTEM"

    mock_system_volume.makedirs("/Library")
    mock_system_volume.makedirs("/Applications")
    mock_system_volume.map_file_fh("/usr/share/firmlinks", BytesIO(b"/Applications\tApplications\n/Library\tLibrary\n"))

    mock_data_volume = VirtualFilesystem()
    mock_data_volume.__type__ = "apfs"
    mock_data_volume.apfs = Mock()
    mock_data_volume.apfs.role = Mock()
    mock_data_volume.apfs.role.name = "DATA"
    mock_data_volume.makedirs("/Library/something")
    mock_data_volume.makedirs("/Applications/Some.app")

    target_bare.filesystems.add(mock_system_volume)
    target_bare.filesystems.add(mock_data_volume)

    assert MacOSPlugin.detect(target_bare) is mock_system_volume
    target_bare._os_plugin = MacOSPlugin
    target_bare.apply()

    assert target_bare.fs.exists("/Applications")
    assert target_bare.fs.exists("/Library")
    assert target_bare.fs.exists("/Applications/Some.app")
    assert target_bare.fs.exists("/Library/something")
