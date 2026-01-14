from __future__ import annotations

import os

from dissect.target import container
from dissect.target.containers.qcow2 import QCow2Container
from tests._utils import absolute_path


def test_qcow2_container() -> None:
    """Test that QCOW2 containers are properly opened."""
    path = absolute_path("_data/containers/qcow2/small.qcow2")

    fh = container.open(path)
    assert isinstance(fh, QCow2Container)
    a = fh.read(20)
    # trailing \x00 are expected. This is the same when using qemu-nbd
    assert a == b"testdissecteqcow2\n\x00\x00"
    assert fh.tell() == 20
    fh.seek(0, whence=os.SEEK_SET)
    assert fh.read(20) == b"testdissecteqcow2\n\x00\x00"
    fh.close()
