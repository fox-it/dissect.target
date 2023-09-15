from io import BytesIO

import pytest

from dissect.target.plugins.os.unix.bsd.freebsd._os import FreeBsdPlugin
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin

from ._utils import absolute_path


@pytest.mark.parametrize(
    "data_path, target_path, expected_version, os_plugin",
    [
        (
            "data/plugins/os/unix/linux/debian/debian-os-release",
            "/etc/os-release",
            "Debian GNU/Linux 11 (bullseye)",
            LinuxPlugin,
        ),
        (
            "data/plugins/os/unix/linux/debian/ubuntu-os-release",
            "/etc/os-release",
            "Ubuntu 22.04.2 LTS (Jammy Jellyfish)",
            LinuxPlugin,
        ),
        ("data/plugins/os/unix/linux/redhat/centos-os-release", "/etc/os-release", "CentOS Linux 8", LinuxPlugin),
        (
            "data/plugins/os/unix/linux/redhat/fedora-os-release",
            "/etc/os-release",
            "Fedora Linux 37 (Container Image)",
            LinuxPlugin,
        ),
        ("data/plugins/os/unix/linux/suse/opensuse-os-release", "/etc/os-release", "openSUSE Leap 15.4", LinuxPlugin),
        ("data/plugins/os/unix/linux/debian/ubuntu-lsb-release", "/etc/lsb-release", "Ubuntu 22.04.2 LTS", LinuxPlugin),
        (
            "data/plugins/os/unix/bsd/freebsd/freebsd-freebsd-version",
            "/bin/freebsd-version",
            "13.0-RELEASE",
            FreeBsdPlugin,
        ),
    ],
)
def test_unix_version_detection(fs_unix, target_unix, data_path, target_path, expected_version, os_plugin):
    fs_unix.map_file(target_path, absolute_path(data_path))
    target_unix.add_plugin(os_plugin)

    assert target_unix.version == expected_version


@pytest.mark.parametrize(
    "content, target_path, os_plugin",
    [
        ("Fedora release 37 (Thirty Seven)", "/etc/fedora-release", LinuxPlugin),
        ("CentOS Linux release 8.4.2105", "/etc/centos-release", LinuxPlugin),
    ],
)
def test_unix_version_detection_short(fs_unix, target_unix, content, target_path, os_plugin):
    fs_unix.map_file_fh(target_path, BytesIO(content.encode()))
    target_unix.add_plugin(os_plugin)

    assert target_unix.version == content


def test_unix_os_release_directory_regression(fs_unix, target_unix):
    fs_unix.map_file_fh(
        "/etc/upstream-release/lsb-release",
        BytesIO(
            b"DISTRIB_ID=Ubuntu\n"
            b"DISTRIB_RELEASE=16.04\n"
            b"DISTRIB_CODENAME=xenial\n"
            b'DISTRIB_DESCRIPTION="Ubuntu 16.04 LTS"'
        ),
    )
    fs_unix.map_file_fh(
        "/etc/lsb-release",
        BytesIO(
            b"DISTRIB_ID=LinuxMint\n"
            b"DISTRIB_RELEASE=19\n"
            b"DISTRIB_CODENAME=tara\n"
            b'DISTRIB_DESCRIPTION="Linux Mint 19 Tara"'
        ),
    )
    target_unix.add_plugin(LinuxPlugin)
    assert target_unix.version == "Linux Mint 19 Tara"
