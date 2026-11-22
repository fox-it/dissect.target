from __future__ import annotations

import io

from dissect.target import container
from dissect.target.containers.raw import RawContainer
from tests._utils import absolute_path


def test_raw_container() -> None:
    """Test that a raw containers are properly opened.

    Generated with::

        echo "TestDissectRaw" > small.txt
    """
    path = absolute_path("_data/containers/raw/small.txt")

    fh = container.open(path)
    assert isinstance(fh, RawContainer)
    a = fh.read(20)
    # trailing \x00 are expected. This is the same when using qemu-nbd
    assert a == b"TestDissectRaw\n"
    assert fh.tell() == 15
    fh.seek(0, whence=io.SEEK_SET)
    assert fh.read(20) == b"TestDissectRaw\n"
    fh.close()
