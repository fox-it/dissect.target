from __future__ import annotations

from io import BytesIO
from textwrap import dedent
from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.etc.fstab import FstabPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    import pytest

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_etc_fstab_plugin(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fstab_file = absolute_path("_data/plugins/os/unix/etc/fstab")
    fs_unix.map_file("/etc/fstab", fstab_file)
    target_unix_users.add_plugin(FstabPlugin)

    results = list(target_unix_users.etc.fstab())
    assert len(results) == 13



def test_etc_fstab_plugin_invalid(
    caplog: pytest.LogCaptureFixture, target_unix_users: Target, fs_unix: VirtualFilesystem
) -> None:
    """Test if we can parse invalid fstab entries."""
    fstab_invalid = """
    UUID=1349-vbay-as78-efeh  /home  ext4  defaults  0  2
    /dev/sdc1  /mnt/windows  ntfs-3g  ro,uid=1000  0  0
    192.168.1.50:/exports/share  /mnt/nfs  nfs  _netdev,auto  0  0
    UUID=1234-abcd  /data  ext4  defaults
    /dev/sdc2  /mnt/usb  ext3  sw  2  0
    /dev/sdb2  none  swap  sw  0  0
    /dev/sdd1  /  ext4  sw  0  a
    /dev/sdb1  /mnt/my backup  ext4  defaults  0  0
    """
    fs_unix.map_file_fh("/etc/fstab", BytesIO(dedent(fstab_invalid).encode()))
    target_unix_users.add_plugin(FstabPlugin)

    results = list(target_unix_users.etc.fstab())
    assert len(results) == 5
    assert results[0].device_path == "UUID=1349-vbay-as78-efeh"
    assert results[0].mount_path == "/home"
    assert results[1].device_path == "/dev/sdc1"
    assert results[2].fs_type == "nfs"
    assert results[3].device_path == "UUID=1234-abcd"
    assert results[4].mount_path == "none"
