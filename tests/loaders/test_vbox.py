from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

from dissect.target.loader import open as loader_open
from dissect.target.loaders.vbox import VBoxLoader
from dissect.target.target import Target

if TYPE_CHECKING:
    from pathlib import Path


def test_target_open(tmp_path: Path) -> None:
    """Test that we correctly use ``VBoxLoader`` when opening a ``Target``."""
    path = tmp_path / "test.vbox"
    path.touch()

    with (
        patch("dissect.target.loaders.vbox.VBox") as mock_vbox,
        patch("dissect.target.loaders.ovf.container.open"),
        patch("dissect.target.target.Target.apply"),
    ):
        mock_vbox.return_value = mock_vbox
        mock_vbox.disks.return_value = ["mock.vdi"]

        for target in (Target.open(path), next(Target.open_all(path), None)):
            assert target is not None
            assert isinstance(target._loader, VBoxLoader)
            assert target.path == path


def test_loader(tmp_path: Path) -> None:
    path = tmp_path / "test.vbox"
    path.touch()

    with (
        patch("dissect.target.loaders.vbox.VBox") as mock_vbox,
        patch("dissect.target.loaders.ovf.container.open") as mock_container_open,
    ):
        mock_vbox.return_value = mock_vbox
        mock_vbox.disks.return_value = ["mock.vdi"]

        loader = loader_open(path)
        assert isinstance(loader, VBoxLoader)

        t = Target()
        loader.map(t)

        assert len(t.disks) == 1
        mock_container_open.assert_called_with(loader.base_path / "mock.vdi")
