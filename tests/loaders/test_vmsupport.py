from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.tar import TarLoader
from dissect.target.loaders.vmsupport import VmSupportLoader, VmSupportTarSubloader
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from pytest_benchmark.fixture import BenchmarkFixture

    from dissect.target.loader import Loader


@pytest.fixture
def mock_vmsupport_dir(tmp_path: Path) -> Path:
    root = tmp_path / "esx-localhost-2026-01-09--16.04-135806"

    (root / "etc" / "vmware").mkdir(parents=True)
    (root / "action.log").write_bytes(b"")
    (root / "error.log").write_bytes(b"")
    (root / "etc" / "vmware" / "esx.conf").write_bytes(b'/resourceGroups/version = "8.0.3"\n')
    return tmp_path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
# vmsupport files with commands/vsi_traverse_-s* removed (~300mo)
@pytest.mark.parametrize(
    ("path", "loader"),
    [
        ("_data/loaders/vmsupport/esx-localhost6-2026-01-12--13.56-2107676.tar.gz", TarLoader),
        ("_data/loaders/vmsupport/esx-localhost7-2026-01-20--09.27-139218.tgz", TarLoader),
        ("_data/loaders/vmsupport/esx-localhost8-2026-01-09--16.04-135806.tgz", TarLoader),
        ("_data/loaders/vmsupport/esx-testdissecthostname9-2026-01-20--16.28-133046.tgz", TarLoader),
        ("mock_vmsupport_dir", VmSupportLoader),
    ],
)
def test_target_open(
    opener: Callable[[str | Path], Target], path: str, loader: type[Loader], mock_vmsupport_dir: Path
) -> None:
    """Test that we correctly use the ESXi vm-support loaders when opening a ``Target``."""
    path = mock_vmsupport_dir if path == "mock_vmsupport_dir" else absolute_path(path)

    with patch("dissect.target.target.Target.apply"):
        target = opener(path)

        assert isinstance(target._loader, loader)
        if isinstance(target._loader, TarLoader):
            assert isinstance(target._loader.subloader, VmSupportTarSubloader)
        assert target.path == path


@pytest.mark.parametrize(
    "data_path",
    [
        "_data/loaders/vmsupport/esx-localhost6-2026-01-12--13.56-2107676.tar.gz",
        "_data/loaders/vmsupport/esx-localhost7-2026-01-20--09.27-139218.tgz",
        "_data/loaders/vmsupport/esx-localhost8-2026-01-09--16.04-135806.tgz",
        "_data/loaders/vmsupport/esx-testdissecthostname9-2026-01-20--16.28-133046.tgz",
    ],
)
def test_compressed_tar(data_path: str) -> None:
    """Test if we map a compressed vm support tar image correctly."""
    path = absolute_path(data_path)

    loader = loader_open(path)
    assert isinstance(loader, TarLoader)

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, VmSupportTarSubloader)
    assert len(t.filesystems) == 1

    t.apply()
    test_file = t.fs.path("/etc/vmware/esx.conf")
    assert test_file.exists()
    assert test_file.is_file()
    assert b"/resourceGroups/version" in test_file.open().read()


def test_dir(mock_vmsupport_dir: Path) -> None:
    """Test if we map an extracted vm support directory correctly."""

    loader = loader_open(mock_vmsupport_dir)
    assert isinstance(loader, VmSupportLoader)

    t = Target()
    loader.map(t)
    assert len(t.filesystems) == 1

    t.apply()
    test_file = t.fs.path("etc/vmware/esx.conf")
    assert test_file.exists()
    assert test_file.is_file()
    assert test_file.open().readline() == b'/resourceGroups/version = "8.0.3"\n'


@pytest.mark.parametrize(
    ("archive", "loader"),
    [
        ("_data/loaders/vmsupport/esx-localhost6-2026-01-12--13.56-2107676.tar.gz", TarLoader),
        ("_data/loaders/vmsupport/esx-localhost7-2026-01-20--09.27-139218.tgz", TarLoader),
        ("_data/loaders/vmsupport/esx-localhost8-2026-01-09--16.04-135806.tgz", TarLoader),
        ("_data/loaders/vmsupport/esx-testdissecthostname9-2026-01-20--16.28-133046.tgz", TarLoader),
    ],
)
@pytest.mark.benchmark
def test_benchmark(benchmark: BenchmarkFixture, archive: str, loader: type[Loader]) -> None:
    file = absolute_path(archive)

    benchmark(lambda: loader(file).map(Target()))
