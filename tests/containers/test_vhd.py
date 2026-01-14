from __future__ import annotations

import gzip
import os

from dissect.target import container
from dissect.target.containers.vhd import VhdContainer
from tests._utils import absolute_path


def test_vhd_container() -> None:
    """Test that VHD containers are properly opened."""
    path = absolute_path("_data/containers/vhd/small.vhd.gz")
    gz_file = gzip.GzipFile(path)
    fh = container.open(gz_file)
    assert isinstance(fh, VhdContainer)
    a = fh.read(20)
    assert a == b"\x00" * 20
    assert fh.tell() == 20
    fh.seek(0, whence=os.SEEK_END)
    assert fh.tell() == 4194304
    fh.close()
    gz_file.close()
