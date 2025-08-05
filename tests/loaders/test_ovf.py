from __future__ import annotations

from typing import TYPE_CHECKING, Callable
from unittest.mock import MagicMock, patch

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.ovf import OvfLoader
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
    """Test that we correctly use ``OvfLoader`` when opening a ``Target``."""
    path = tmp_path / "test.ovf"
    path.touch()

    with (
        patch("dissect.hypervisor.descriptor.ovf.OVF") as mock_ovf,
        patch("dissect.target.container.open"),
        patch("dissect.target.target.Target.apply"),
    ):
        mock_ovf.return_value = MagicMock()
        mock_ovf.disks.return_value = ["disk.vmdk"]

        target = opener(path)
        assert isinstance(target._loader, OvfLoader)
        assert target.path == path


def test_loader(tmp_path: Path) -> None:
    """Test that ``OvfLoader`` correctly loads an OVF file and its disks."""
    path = tmp_path / "test.ovf"
    path.touch()

    with (
        patch("dissect.hypervisor.descriptor.ovf.OVF") as mock_ovf,
        patch("dissect.target.container.open") as mock_container_open,
    ):
        mock_ovf.return_value = mock_ovf
        mock_ovf.disks.return_value = ["disk.vmdk"]

        loader = loader_open(path)
        assert isinstance(loader, OvfLoader)

        t = Target()
        loader.map(t)

        assert len(t.disks) == 1
        mock_container_open.assert_called_with(tmp_path.resolve() / "disk.vmdk")
