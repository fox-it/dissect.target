from __future__ import annotations

import io

from dissect.target import container
from dissect.target.containers.qcow2 import QCow2Container
from dissect.target.filesystem import VirtualFilesystem
from tests._utils import absolute_path


def test_qcow2_container() -> None:
    """Test that QCOW2 containers are properly opened.

    ```
    echo "testdissecteqcow2" > small.txt
    qemu-img convert -f raw -O qcow2 small.txt small.qcow2
    ```
    """
    path = absolute_path("_data/containers/qcow2/small.qcow2")

    fh = container.open(path)
    assert isinstance(fh, QCow2Container)
    a = fh.read(20)
    # trailing \x00 are expected. This is the same when using qemu-nbd
    assert a == b"testdissecteqcow2\n\x00\x00"
    assert fh.tell() == 20
    fh.seek(0, whence=io.SEEK_SET)
    assert fh.read(20) == b"testdissecteqcow2\n\x00\x00"
    fh.close()


def test_qcow2_detect_path() -> None:
    """Test that QCOW2 containers are properly opened, when using the extension based matching."""
    vfs = VirtualFilesystem()
    vfs.map_file("small.qcow2", absolute_path("_data/containers/qcow2/small.qcow2"))
    fh = container.open(vfs.path("small.qcow2"))
    assert isinstance(fh, QCow2Container)
    a = fh.read(20)
    # trailing \x00 are expected. This is the same when using qemu-nbd
    assert a == b"testdissecteqcow2\n\x00\x00"
    assert fh.tell() == 20
    fh.seek(0, whence=io.SEEK_SET)
    assert fh.read(20) == b"testdissecteqcow2\n\x00\x00"
