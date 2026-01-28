from __future__ import annotations

import gzip
import io

from dissect.target import container
from dissect.target.containers.vdi import VdiContainer
from dissect.target.filesystem import VirtualFilesystem
from tests._utils import absolute_path


def test_vdi_container() -> None:
    """Test that VDI containers are properly opened.

    ```
    VBoxManage createmedium disk --filename "./tests/small.vdi" --size 2 --format=VDI
    ```
    """
    path = absolute_path("_data/containers/vdi/small.vdi.gz")
    gz_file = gzip.GzipFile(path)
    fh = container.open(gz_file)
    assert isinstance(fh, VdiContainer)
    a = fh.read(20)
    assert a == b"\x00" * 20
    assert fh.tell() == 20
    fh.seek(0, whence=io.SEEK_END)
    assert fh.tell() == 2097152
    fh.close()
    gz_file.close()


def test_vdi_detect_path() -> None:
    """Test that VDI containers are properly opened, when using the extension based matching."""
    vfs = VirtualFilesystem()
    vfs.map_file("small.vdi", absolute_path("_data/containers/vdi/small.vdi.gz"), compression="gzip")
    fh = container.open(vfs.path("small.vdi"))
    assert isinstance(fh, VdiContainer)
    a = fh.read(20)
    assert a == b"\x00" * 20
    assert fh.tell() == 20
    fh.seek(0, whence=io.SEEK_END)
    assert fh.tell() == 2097152
    fh.close()
