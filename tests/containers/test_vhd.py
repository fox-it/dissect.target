from __future__ import annotations

import gzip
import io

from dissect.target import container
from dissect.target.containers.vhd import VhdContainer
from dissect.target.filesystem import VirtualFilesystem
from tests._utils import absolute_path


def test_vhd_container() -> None:
    """Test that VHD containers are properly opened.

    Generated with::

        VBoxManage createmedium disk --filename "./small.vhd" --size 2 --format=VHD
    """
    path = absolute_path("_data/containers/vhd/small.vhd.gz")
    gz_file = gzip.GzipFile(path)
    fh = container.open(gz_file)
    assert isinstance(fh, VhdContainer)
    a = fh.read(20)
    assert a == b"\x00" * 20
    assert fh.tell() == 20
    fh.seek(0, whence=io.SEEK_END)
    assert fh.tell() == 2097152
    fh.close()
    gz_file.close()


def test_VHD_detect_path() -> None:
    """Test that VDI containers are properly opened, when using the extension based matching."""
    vfs = VirtualFilesystem()
    vfs.map_file("small.vhd", absolute_path("_data/containers/vhd/small.vhd.gz"), compression="gzip")
    fh = container.open(vfs.path("small.vhd"))
    assert isinstance(fh, VhdContainer)
    a = fh.read(20)
    assert a == b"\x00" * 20
    assert fh.tell() == 20
    fh.seek(0, whence=io.SEEK_END)
    assert fh.tell() == 2097152
