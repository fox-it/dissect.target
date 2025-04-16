from __future__ import annotations

from pathlib import Path

from dissect.target.filesystems.cpio import CpioFilesystem
from tests._utils import absolute_path


def test_cpio_uncompressed() -> None:
    cpio_path = Path(absolute_path("_data/filesystems/cpio/initrd.img-6.1.0-17-amd64"))

    with cpio_path.open("rb") as fh:
        assert CpioFilesystem.detect(fh)

        fs = CpioFilesystem(fh)
        assert [f.name for f in fs.path("/").iterdir()] == ["kernel"]


def test_cpio_compressed_zstd() -> None:
    cpio_path = Path(absolute_path("_data/filesystems/cpio/initrd.img-6.1.0-15-amd64"))

    with cpio_path.open("rb") as fh:
        assert CpioFilesystem.detect(fh)

        fs = CpioFilesystem(fh)
        assert [f.name for f in fs.path("/").iterdir()] == [
            "bin",
            "conf",
            "etc",
            "init",
            "lib",
            "lib64",
            "run",
            "sbin",
            "scripts",
            "usr",
        ]
