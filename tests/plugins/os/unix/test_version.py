from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.bsd.freebsd._os import FreeBsdPlugin
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.plugin import OSPlugin
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("data_path", "target_path", "expected_version", "os_plugin"),
    [
        (
            "_data/plugins/os/unix/linux/debian/_os/debian-os-release",
            "/etc/os-release",
            "Debian GNU/Linux 11 (bullseye)",
            LinuxPlugin,
        ),
        (
            "_data/plugins/os/unix/linux/debian/_os/ubuntu-os-release",
            "/etc/os-release",
            "Ubuntu 22.04.2 LTS (Jammy Jellyfish)",
            LinuxPlugin,
        ),
        (
            "_data/plugins/os/unix/linux/redhat/_os/centos-os-release",
            "/etc/os-release",
            "CentOS Linux 8",
            LinuxPlugin,
        ),
        (
            "_data/plugins/os/unix/linux/redhat/_os/fedora-os-release",
            "/etc/os-release",
            "Fedora Linux 37 (Container Image)",
            LinuxPlugin,
        ),
        (
            "_data/plugins/os/unix/linux/suse/_os/opensuse-os-release",
            "/etc/os-release",
            "openSUSE Leap 15.4",
            LinuxPlugin,
        ),
        (
            "_data/plugins/os/unix/linux/debian/_os/ubuntu-lsb-release",
            "/etc/lsb-release",
            "Ubuntu 22.04.2 LTS",
            LinuxPlugin,
        ),
        (
            "_data/plugins/os/unix/bsd/freebsd/_os/freebsd-freebsd-version",
            "/bin/freebsd-version",
            "13.0-RELEASE",
            FreeBsdPlugin,
        ),
        (
            "_data/plugins/os/unix/linux/alpine/_os/alpine-os-release",
            "/etc/os-release",
            "Alpine Linux 3.18.4",
            LinuxPlugin,
        ),
    ],
)
def test_unix_version_detection(
    target_unix: Target,
    fs_unix: VirtualFilesystem,
    data_path: str,
    target_path: str,
    expected_version: str,
    os_plugin: type[OSPlugin],
) -> None:
    fs_unix.map_file(target_path, absolute_path(data_path))
    target_unix.add_plugin(os_plugin)

    assert target_unix.version == expected_version


@pytest.mark.parametrize(
    ("content", "target_path", "os_plugin"),
    [
        ("Fedora release 37 (Thirty Seven)", "/etc/fedora-release", LinuxPlugin),
        ("CentOS Linux release 8.4.2105", "/etc/centos-release", LinuxPlugin),
    ],
)
def test_unix_version_detection_short(
    target_unix: Target, fs_unix: VirtualFilesystem, content: str, target_path: str, os_plugin: type[OSPlugin]
) -> None:
    fs_unix.map_file_fh(target_path, BytesIO(content.encode()))
    target_unix.add_plugin(os_plugin)

    assert target_unix.version == content


def test_unix_os_release_directory_regression(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh(
        "/etc/upstream-release/lsb-release",
        BytesIO(
            b'DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=16.04\nDISTRIB_CODENAME=xenial\nDISTRIB_DESCRIPTION="Ubuntu 16.04 LTS"'
        ),
    )
    fs_unix.map_file_fh(
        "/etc/lsb-release",
        BytesIO(
            b'DISTRIB_ID=LinuxMint\nDISTRIB_RELEASE=19\nDISTRIB_CODENAME=tara\nDISTRIB_DESCRIPTION="Linux Mint 19 Tara"'
        ),
    )
    target_unix.add_plugin(LinuxPlugin)
    assert target_unix.version == "Linux Mint 19 Tara"
