from __future__ import annotations

from pathlib import Path

from dissect.target.filesystems.vmtar import VmtarFilesystem
from tests._utils import absolute_path


def test_filesystems_vmtar() -> None:
    vmtar_path = Path(absolute_path("_data/filesystems/vmtar/simple.vmtar"))

    with vmtar_path.open("rb") as fh:
        assert VmtarFilesystem.detect(fh)

        fs = VmtarFilesystem(fh)
        assert [f.name for f in fs.path("/").iterdir()] == ["hello_world.txt"]
        assert fs.get("hello_world.txt").open().read() == b"hello_from_a_tar_file\n"
