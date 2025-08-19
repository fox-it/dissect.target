from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.tar import TarLoader
from dissect.target.loaders.uac import UacLoader, UacTarSubloader, UacZipSubLoader
from dissect.target.loaders.zip import ZipLoader
from dissect.target.target import Target
from tests._utils import absolute_path, mkdirs

if TYPE_CHECKING:
    from pathlib import Path

    from pytest_benchmark.fixture import BenchmarkFixture

    from dissect.target.loader import Loader


def test_uac_loader_compressed_tar(target_bare: Target) -> None:
    """Test if we map a compressed UAC tar image correctly."""
    path = absolute_path("_data/loaders/uac/uac-2e44ea6da71d-linux-20250717143111.tar.gz")

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    loader.map(target_bare)
    assert isinstance(loader.subloader, UacTarSubloader)
    assert len(target_bare.filesystems) == 1

    target_bare.apply()
    test_file = target_bare.fs.path("/etc/passwd")
    assert test_file.exists()
    assert test_file.is_file()
    assert test_file.open().readline() == b"root:x:0:0:root:/root:/bin/bash\n"


def test_uac_loader_compressed_zip(target_bare: Target) -> None:
    """Test if we map a compressed UAC zip image correctly."""
    path = absolute_path("_data/loaders/uac/uac-2e44ea6da71d-linux-20250717143106.zip")

    loader = loader_open(path)
    assert isinstance(loader, ZipLoader)

    loader.map(target_bare)
    assert isinstance(loader.subloader, UacZipSubLoader)
    assert len(target_bare.filesystems) == 1

    target_bare.apply()
    test_file = target_bare.fs.path("etc/passwd")
    assert test_file.exists()
    assert test_file.is_file()
    assert test_file.open().readline() == b"root:x:0:0:root:/root:/bin/bash\n"


def test_uac_loader_dir(target_bare: Target, tmp_path: Path) -> None:
    """Test if we map an extracted UAC directory correctly."""
    root = tmp_path
    mkdirs(root / "[root]", ["etc", "var"])
    (root / "uac.log").write_bytes(b"")
    (root / "[root]" / "etc" / "passwd").write_bytes(b"root:x:0:0:root:/root:/bin/bash\n")

    loader = loader_open(root)
    assert isinstance(loader, UacLoader)

    loader.map(target_bare)
    assert len(target_bare.filesystems) == 1

    target_bare.apply()
    test_file = target_bare.fs.path("etc/passwd")
    assert test_file.exists()
    assert test_file.is_file()
    assert test_file.open().readline() == b"root:x:0:0:root:/root:/bin/bash\n"


@pytest.mark.parametrize(
    ("archive", "loader"),
    [
        ("_data/loaders/uac/uac-2e44ea6da71d-linux-20250717143111.tar.gz", TarLoader),
        ("_data/loaders/uac/uac-2e44ea6da71d-linux-20250717143106.zip", ZipLoader),
    ],
)
@pytest.mark.benchmark
def test_benchmark(benchmark: BenchmarkFixture, archive: str, loader: type[Loader]) -> None:
    file = absolute_path(archive)

    benchmark(lambda: loader(file).map(Target()))
