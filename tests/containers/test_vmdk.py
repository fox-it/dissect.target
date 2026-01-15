from __future__ import annotations

import gzip
import io

from dissect.target import container
from dissect.target.containers.vmdk import VmdkContainer
from tests._utils import absolute_path


def test_vmdk_container() -> None:
    """Test that VMDK containers are properly opened."""
    path = absolute_path("_data/containers/vmdk/small.vmdk.gz")
    gz_file = gzip.GzipFile(path)
    fh = container.open(gz_file)
    assert isinstance(fh, VmdkContainer)
    a = fh.read(20)
    assert a == b"\x00" * 20
    assert fh.tell() == 20
    fh.seek(0, whence=io.SEEK_END)
    assert fh.tell() == 4194304
    fh.close()
    gz_file.close()
