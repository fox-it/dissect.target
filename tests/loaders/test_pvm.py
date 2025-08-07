from __future__ import annotations

from typing import TYPE_CHECKING, Callable
from unittest.mock import patch

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.pvm import PvmLoader
from dissect.target.target import Target
from tests._utils import mkdirs

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def mock_pvm_dir(tmp_path: Path) -> Iterator[Path]:
    mkdirs(tmp_path, ["Test.pvm"])
    (tmp_path / "Test.pvm" / "config.pvs").touch()

    with patch("dissect.hypervisor.descriptor.pvs.PVS") as mock_pvs:
        mock_pvs.return_value = mock_pvs
        mock_pvs.disks.return_value = ["mock.hdd"]

        yield tmp_path / "Test.pvm"


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target], mock_pvm_dir: Path) -> None:
    """Test that we correctly use ``PvmLoader`` when opening a ``Target``."""
    with patch("dissect.target.container.open"), patch("dissect.target.target.Target.apply"):
        target = opener(mock_pvm_dir)
        assert isinstance(target._loader, PvmLoader)
        assert target.path == mock_pvm_dir


def test_loader(mock_pvm_dir: Path) -> None:
    """Test that ``PvmLoader`` correctly loads a PVM file and its disks."""
    with patch("dissect.target.container.open") as mock_container_open:
        loader = loader_open(mock_pvm_dir)
        assert isinstance(loader, PvmLoader)

        t = Target()
        loader.map(t)

        assert len(t.disks) == 1
        mock_container_open.assert_called_with(mock_pvm_dir.resolve() / "mock.hdd")
