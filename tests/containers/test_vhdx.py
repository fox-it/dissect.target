from __future__ import annotations

import gzip
import io

from dissect.target import container
from dissect.target.containers.vhdx import VhdxContainer
from dissect.target.filesystem import VirtualFilesystem
from tests._utils import absolute_path


def test_vhdx_container() -> None:
    """Test that VHDX containers are properly opened.

    VBoxManage does not allow to create vhdx. We convert a previously generated vdi to vhdx

    Generated with::

        qemu-img convert -f vdi -O vhdx small.vdi small.vhdx
    """
    path = absolute_path("_data/containers/vhdx/small.vhdx.gz")
    gz_file = gzip.GzipFile(path)
    fh = container.open(gz_file)
    assert isinstance(fh, VhdxContainer)
    a = fh.read(20)
    assert a == b"\x00" * 20
    assert fh.tell() == 20
    fh.seek(0, whence=io.SEEK_END)
    assert fh.tell() == 2097152
    fh.close()
    gz_file.close()


def test_vhdx_detect_path() -> None:
    """Test that VHDX containers are properly opened, when using the extension based matching."""
    vfs = VirtualFilesystem()
    vfs.map_file("small.vhdx", absolute_path("_data/containers/vhdx/small.vhdx.gz"), compression="gzip")
    fh = container.open(vfs.path("small.vhdx"))
    assert isinstance(fh, VhdxContainer)
    a = fh.read(20)
    assert a == b"\x00" * 20
    assert fh.tell() == 20
    fh.seek(0, whence=io.SEEK_END)
    assert fh.tell() == 2097152
