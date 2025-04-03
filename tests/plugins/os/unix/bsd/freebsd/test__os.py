from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugin import OperatingSystem
from dissect.target.plugins.os.unix.bsd.freebsd._os import FreeBsdPlugin
from dissect.target.target import Target
from tests._utils import absolute_path


def test_bsd_freebsd_os_detection(target_bare: Target) -> None:
    """test if we detect FreeBSD correctly."""

    fs = VirtualFilesystem()
    fs.makedirs("/net")
    fs.map_file("/bin/freebsd-version", absolute_path("_data/plugins/os/unix/bsd/freebsd/freebsd-freebsd-version"))

    target_bare.filesystems.add(fs)
    target_bare.apply()

    assert FreeBsdPlugin.detect(target_bare)
    assert isinstance(target_bare._os, FreeBsdPlugin)
    assert target_bare.os == OperatingSystem.BSD
