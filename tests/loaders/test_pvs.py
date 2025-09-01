from __future__ import annotations

from typing import TYPE_CHECKING, Callable
from unittest.mock import patch

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.pvs import PvsLoader
from dissect.target.target import Target

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target], tmp_path: Path) -> None:
    """Test that we correctly use ``PvsLoader`` when opening a ``Target``."""
    path = tmp_path / "config.pvs"
    path.touch()

    with (
        patch("dissect.hypervisor.descriptor.pvs.PVS") as mock_pvs,
        patch("dissect.target.container.open"),
        patch("dissect.target.target.Target.apply"),
    ):
        mock_pvs.return_value = mock_pvs
        mock_pvs.disks.return_value = ["mock.hdd"]

        target = opener(path)
        assert isinstance(target._loader, PvsLoader)
        assert target.path == path


def test_loader(tmp_path: Path) -> None:
    """Test that ``PvsLoader`` correctly loads a PVS file and its disks."""
    path = tmp_path / "config.pvs"
    path.touch()

    with patch("dissect.hypervisor.descriptor.pvs.PVS") as mock_pvs, patch("dissect.target.container.open"):
        mock_pvs.return_value = mock_pvs
        mock_pvs.disks.return_value = ["mock.hdd"]

        loader = loader_open(path)
        assert isinstance(loader, PvsLoader)

        t = Target()
        loader.map(t)

        assert len(t.disks) == 1
