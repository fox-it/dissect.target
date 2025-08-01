from __future__ import annotations

from unittest.mock import patch

from dissect.target.loader import open as loader_open
from dissect.target.loaders.asdf import AsdfLoader
from dissect.target.target import Target
from tests._utils import absolute_path


def test_target_open() -> None:
    """Test that we correctly use ``AsdfLoader`` when opening a ``Target``."""
    path = absolute_path("_data/loaders/asdf/metadata.asdf")

    with patch("dissect.target.target.Target.apply"):
        for target in (Target.open(path), next(Target.open_all(path), None)):
            assert target is not None
            assert isinstance(target._loader, AsdfLoader)


def test_loader_metadata() -> None:
    """Test the ASDF loader with metadata."""
    path = absolute_path("_data/loaders/asdf/metadata.asdf")

    loader = loader_open(path)
    assert isinstance(loader, AsdfLoader)

    t = Target()
    loader.map(t)
    assert len(t.filesystems) == 0

    assert list(map(str, t.fs.path("/").rglob("*"))) == [
        "/$asdf$",
        "/$asdf$/file_1",
        "/$asdf$/dir",
        "/$asdf$/dir/file_2",
    ]
