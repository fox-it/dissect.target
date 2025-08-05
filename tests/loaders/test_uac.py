from __future__ import annotations

from typing import TYPE_CHECKING, Callable
from unittest.mock import patch

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


@pytest.fixture
def mock_uac_dir(tmp_path: Path) -> Path:
    root = tmp_path
    mkdirs(root / "[root]", ["etc", "var"])
    (root / "uac.log").write_bytes(b"")
    (root / "[root]" / "etc" / "passwd").write_bytes(b"root:x:0:0:root:/root:/bin/bash\n")
    return tmp_path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
@pytest.mark.parametrize(
    ("path", "loader"),
    [
        ("_data/loaders/uac/uac-2e44ea6da71d-linux-20250717143111.tar.gz", TarLoader),
        ("_data/loaders/uac/uac-2e44ea6da71d-linux-20250717143106.zip", ZipLoader),
        ("mock_uac_dir", UacLoader),
    ],
)
def test_target_open(
    opener: Callable[[str | Path], Target], path: str, loader: type[Loader], mock_uac_dir: Path
) -> None:
    """Test that we correctly use the UAC loaders when opening a ``Target``."""
    path = mock_uac_dir if path == "mock_uac_dir" else absolute_path(path)

    with patch("dissect.target.target.Target.apply"):
        target = opener(path)

        assert isinstance(target._loader, loader)
        if isinstance(target._loader, TarLoader):
            assert isinstance(target._loader.subloader, UacTarSubloader)
        elif isinstance(target._loader, ZipLoader):
            assert isinstance(target._loader.subloader, UacZipSubLoader)
        assert target.path == path


def test_compressed_tar() -> None:
    """Test if we map a compressed UAC tar image correctly."""
    path = absolute_path("_data/loaders/uac/uac-2e44ea6da71d-linux-20250717143111.tar.gz")

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, UacTarSubloader)
    assert len(t.filesystems) == 1

    t.apply()
    test_file = t.fs.path("/etc/passwd")
    assert test_file.exists()
    assert test_file.is_file()
    assert test_file.open().readline() == b"root:x:0:0:root:/root:/bin/bash\n"


def test_compressed_zip() -> None:
    """Test if we map a compressed UAC zip image correctly."""
    path = absolute_path("_data/loaders/uac/uac-2e44ea6da71d-linux-20250717143106.zip")

    loader = loader_open(path)
    assert isinstance(loader, ZipLoader)

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, UacZipSubLoader)
    assert len(t.filesystems) == 1

    t.apply()
    test_file = t.fs.path("etc/passwd")
    assert test_file.exists()
    assert test_file.is_file()
    assert test_file.open().readline() == b"root:x:0:0:root:/root:/bin/bash\n"


def test_dir(mock_uac_dir: Path) -> None:
    """Test if we map an extracted UAC directory correctly."""

    loader = loader_open(mock_uac_dir)
    assert isinstance(loader, UacLoader)

    t = Target()
    loader.map(t)
    assert len(t.filesystems) == 1

    t.apply()
    test_file = t.fs.path("etc/passwd")
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
