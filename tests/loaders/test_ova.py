from __future__ import annotations

import tarfile
from typing import TYPE_CHECKING, Callable
from unittest.mock import patch

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.ova import OvaLoader
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
    """Test that we correctly use ``OvaLoader`` when opening a ``Target``."""
    path = tmp_path / "test.ova"

    with tarfile.open(path, "w") as tf:
        tf.addfile(tarfile.TarInfo("test.ovf"), b"")
        tf.addfile(tarfile.TarInfo("disk.vmdk"), b"")

    with (
        patch("dissect.hypervisor.descriptor.ovf.OVF") as mock_ovf,
        patch("dissect.target.container.open"),
        patch("dissect.target.target.Target.apply"),
    ):
        mock_ovf.return_value = mock_ovf
        mock_ovf.disks.return_value = ["disk.vmdk"]

        target = opener(path)
        assert isinstance(target._loader, OvaLoader)
        assert target.path == path


def test_loader(tmp_path: Path) -> None:
    """Test that ``OvaLoader`` correctly loads an OVA file and its disks."""
    path = tmp_path / "test.ova"

    with tarfile.open(path, "w") as tf:
        tf.addfile(tarfile.TarInfo("test.ovf"), b"")
        tf.addfile(tarfile.TarInfo("disk.vmdk"), b"")

    with (
        patch("dissect.hypervisor.descriptor.ovf.OVF") as mock_ovf,
        patch("dissect.target.container.open") as mock_container_open,
    ):
        mock_ovf.return_value = mock_ovf
        mock_ovf.disks.return_value = ["disk.vmdk"]

        loader = loader_open(path)
        assert isinstance(loader, OvaLoader)

        t = Target()
        loader.map(t)

        assert len(t.disks) == 1
        mock_container_open.assert_called_with(loader.base_path / "disk.vmdk")
