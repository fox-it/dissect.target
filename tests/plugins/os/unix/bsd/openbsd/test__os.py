from io import BytesIO

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugin import OperatingSystem
from dissect.target.plugins.os.unix.bsd.openbsd._os import OpenBsdPlugin
from dissect.target.target import Target


def test_bsd_openbsd_os_detection(target_bare: Target) -> None:
    """test if we detect OpenBSD correctly."""

    fs = VirtualFilesystem()
    fs.map_file_fh("/etc/myname", BytesIO(b"hostname"))
    fs.makedirs("/bsd")

    target_bare.filesystems.add(fs)
    target_bare.apply()

    assert OpenBsdPlugin.detect(target_bare)
    assert isinstance(target_bare._os, OpenBsdPlugin)
    assert target_bare.os == OperatingSystem.BSD
