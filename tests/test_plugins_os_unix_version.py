from io import BytesIO

import pytest

from dissect.target.plugins.os.unix.linux._os import LinuxPlugin

from ._utils import absolute_path


@pytest.mark.parametrize(
    "data_path, target_path, expected_version",
    [
        ("data/plugins/os/unix/linux/debian/debian-os-release", "/etc/os-release", "Debian GNU/Linux 11 (bullseye)"),
        (
            "data/plugins/os/unix/linux/debian/ubuntu-os-release",
            "/etc/os-release",
            "Ubuntu 22.04.2 LTS (Jammy Jellyfish)",
        ),
        ("data/plugins/os/unix/linux/redhat/centos-os-release", "/etc/os-release", "CentOS Linux 8"),
        ("data/plugins/os/unix/linux/redhat/fedora-os-release", "/etc/os-release", "Fedora Linux 37 (Container Image)"),
        ("data/plugins/os/unix/linux/suse/opensuse-os-release", "/etc/os-release", "openSUSE Leap 15.4"),
    ],
)
def test_unix_version_detection(fs_unix, target_unix, data_path, target_path, expected_version):
    fs_unix.map_file(target_path, absolute_path(data_path))
    target_unix.add_plugin(LinuxPlugin)

    assert target_unix.version == expected_version


@pytest.mark.parametrize(
    "content, target_path",
    [
        ("Fedora release 37 (Thirty Seven)", "/etc/fedora-release"),
        ("CentOS Linux release 8.4.2105", "/etc/centos-release"),
    ],
)
def test_unix_version_detection_short(fs_unix, target_unix, content, target_path):
    fs_unix.map_file_fh(target_path, BytesIO(content.encode()))
    target_unix.add_plugin(LinuxPlugin)

    assert target_unix.version == content
