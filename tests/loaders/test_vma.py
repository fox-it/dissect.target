from __future__ import annotations

from typing import TYPE_CHECKING, Callable

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.vma import VmaLoader
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
    """Test that we correctly use ``VmaLoader`` when opening a ``Target``."""
    path = absolute_path("_data/loaders/vma/vzdump-qemu-6969-2025_08_01-15_24_07.vma")

    target = opener(path)
    assert isinstance(target._loader, VmaLoader)
    assert target.path == path


def test_loader() -> None:
    """Test that ``VmaLoader`` correctly loads a VMA file and its disks."""
    path = absolute_path("_data/loaders/vma/vzdump-qemu-6969-2025_08_01-15_24_07.vma")

    loader = loader_open(path)
    assert isinstance(loader, VmaLoader)

    t = Target()
    loader.map(t)

    assert len(t.disks) == 1
    assert t.disks[0].size == 1073741824
