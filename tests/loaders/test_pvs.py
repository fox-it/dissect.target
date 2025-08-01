from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

from dissect.target.loader import open as loader_open
from dissect.target.loaders.pvs import PvsLoader
from dissect.target.target import Target

if TYPE_CHECKING:
    from pathlib import Path


def test_target_open(tmp_path: Path) -> None:
    """Test that we correctly use ``PvsLoader`` when opening a ``Target``."""
    path = tmp_path / "config.pvs"
    path.touch()

    with (
        patch("dissect.target.loaders.pvs.pvs.PVS") as mock_pvs,
        patch("dissect.target.loaders.pvs.container.open"),
        patch("dissect.target.target.Target.apply"),
    ):
        mock_pvs.return_value = mock_pvs
        mock_pvs.disks.return_value = ["mock.hdd"]

        for target in (Target.open(path), next(Target.open_all(path), None)):
            assert target is not None
            assert isinstance(target._loader, PvsLoader)
            assert target.path == path


def test_loader(tmp_path: Path) -> None:
    """Test that ``PvsLoader`` correctly loads a PVS file and its disks."""
    path = tmp_path / "config.pvs"
    path.touch()

    with patch("dissect.target.loaders.pvs.pvs.PVS") as mock_pvs, patch("dissect.target.loaders.pvs.container.open"):
        mock_pvs.return_value = mock_pvs
        mock_pvs.disks.return_value = ["mock.hdd"]

        loader = loader_open(path)
        assert isinstance(loader, PvsLoader)

        t = Target()
        loader.map(t)

        assert len(t.disks) == 1
