from pathlib import Path

from dissect.target import Target
from dissect.target.loaders.cpio import CpioLoader
from tests._utils import absolute_path


def test_cpio_uncompressed(target_default: Target) -> None:
    cpio_path = Path(absolute_path("_data/loaders/cpio/initrd.img-6.1.0-17-amd64"))
    loader = CpioLoader(cpio_path)

    assert loader.detect(cpio_path)

    loader.map(target_default)
    target_default.apply()

    assert len(target_default.filesystems) == 1
    assert len(target_default.fs.mounts) == 1

    assert [f.name for f in target_default.fs.path("/").iterdir()] == ["kernel"]


def test_cpio_compressed_zstd(target_default: Target) -> None:
    cpio_path = Path(absolute_path("_data/loaders/cpio/initrd.img-6.1.0-15-amd64"))
    loader = CpioLoader(cpio_path)

    assert loader.detect(cpio_path)

    loader.map(target_default)
    target_default.apply()

    assert len(target_default.filesystems) == 1
    assert len(target_default.fs.mounts) == 1

    assert [f.name for f in target_default.fs.path("/").iterdir()] == [
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
