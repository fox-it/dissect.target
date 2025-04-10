from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugin import OperatingSystem
from dissect.target.plugins.os.unix.bsd.freebsd._os import FreeBsdPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_bsd_freebsd_os_detection(target_bare: Target) -> None:
    """Test if we detect FreeBSD correctly."""

    fs = VirtualFilesystem()
    fs.makedirs("/net")
    fs.map_file("/bin/freebsd-version", absolute_path("_data/plugins/os/unix/bsd/freebsd/freebsd-freebsd-version"))

    target_bare.filesystems.add(fs)
    target_bare.apply()

    assert FreeBsdPlugin.detect(target_bare)
    assert isinstance(target_bare._os, FreeBsdPlugin)
    assert target_bare.os == OperatingSystem.BSD
