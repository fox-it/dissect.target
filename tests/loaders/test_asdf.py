from __future__ import annotations

from typing import TYPE_CHECKING, Callable
from unittest.mock import patch

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.asdf import AsdfLoader
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target]) -> None:
    """Test that we correctly use ``AsdfLoader`` when opening a ``Target``."""
    path = absolute_path("_data/loaders/asdf/metadata.asdf")

    with patch("dissect.target.target.Target.apply"):
        target = opener(path)
        assert isinstance(target._loader, AsdfLoader)
        assert target.path == path


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
