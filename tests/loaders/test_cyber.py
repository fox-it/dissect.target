from __future__ import annotations

from unittest.mock import patch

from dissect.target.loader import open as loader_open
from dissect.target.loaders.cyber import CyberLoader
from dissect.target.loaders.tar import TarLoader
from dissect.target.target import Target
from tests._utils import absolute_path


def test_target_open() -> None:
    """Test that we correctly use ``CyberLoader`` when opening a ``Target``."""
    file_path = absolute_path("_data/loaders/tar/test-archive.tar")
    path = f"cyber://{file_path}"

    with patch("dissect.target.loaders.cyber.cyber"):
        for target in (Target.open(path), next(Target.open_all(path), None)):
            assert target is not None
            assert isinstance(target._loader, CyberLoader)
            assert isinstance(target._loader._real, TarLoader)
            assert target.path == file_path


def test_loader() -> None:
    """Test that ``CyberLoader`` correctly loads a Cyber file."""
    path = f"cyber://{absolute_path('_data/loaders/tar/test-archive.tar')}"

    loader = loader_open(path)
    assert isinstance(loader, CyberLoader)
    assert isinstance(loader._real, TarLoader)

    t = Target()
    with patch("dissect.target.loaders.cyber.cyber"):
        loader.map(t)

    assert "cyber" in t.props
