from __future__ import annotations

import os
from pathlib import Path

from dissect.target.filesystems.vmtar import VmtarFilesystem
from dissect.target.helpers.fsutil import open_decompress
from tests._utils import absolute_path


def test_filesystems_vmtar() -> None:
    vmtar_path = Path(absolute_path("_data/filesystems/vmtar/simple.vmtar"))

    with vmtar_path.open("rb") as fh:
        assert VmtarFilesystem.detect(fh)

        fs = VmtarFilesystem(fh)
        assert [f.name for f in fs.path("/").iterdir()] == ["hello_world.txt"]
        assert fs.get("hello_world.txt").open().read() == b"hello_from_a_tar_file\n"


def test_filesystems_vmtar_zstd() -> None:
    vmtar_path = Path(absolute_path("_data/filesystems/vmtar/a.vmtar.zst.gz"))

    with vmtar_path.open("rb") as fh:
        zstd_fh = open_decompress(fileobj=fh)
        vmtar_fh = open_decompress(fileobj=zstd_fh)
        assert vmtar_fh.seek(0, os.SEEK_END) == 4608

    with vmtar_path.open("rb") as fh:
        assert VmtarFilesystem.detect(fh)

        fs = VmtarFilesystem(fh)
        assert fs.get("a/b/c/test.txt").open().read() == b"test_data\nmultiline.txt\n"
