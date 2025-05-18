from io import BytesIO

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugin import OperatingSystem
from dissect.target.plugins.os.unix.linux.redhat._os import RedHatPlugin
from dissect.target.target import Target


@pytest.mark.parametrize(
    "file_name",
    [
        ("/etc/redhat-release"),
        ("/etc/centos-release"),
        ("/etc/fedora-release"),
        ("/etc/sysconfig/network-scripts"),
    ],
)
def test_unix_linux_redhat_os_detection(target_bare: Target, file_name: str) -> None:
    """Test if we detect RedHat OS correctly."""

    fs = VirtualFilesystem()
    fs.map_file_fh(file_name, BytesIO(b""))

    target_bare.filesystems.add(fs)
    target_bare.apply()

    assert RedHatPlugin.detect(target_bare)
    assert isinstance(target_bare._os, RedHatPlugin)
    assert target_bare.os == OperatingSystem.LINUX
