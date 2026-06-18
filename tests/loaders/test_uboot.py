from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.uboot import UBootLoader
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target]) -> None:
    """Test that we correctly use ``UBootLoader`` when opening a ``Target``."""
    path = absolute_path("_data/loaders/uboot/thingino-ajcloud_cp2011_t23n_sc2336_atbm6132bu.bin")

    target = opener(path)
    assert isinstance(target._loader, UBootLoader)
    assert target.path == path


def test_loader() -> None:
    """Test that ``UBootLoader`` correctly loads a U-Boot image."""
    path = absolute_path("_data/loaders/uboot/thingino-ajcloud_cp2011_t23n_sc2336_atbm6132bu.bin")

    loader = loader_open(path)
    assert isinstance(loader, UBootLoader)

    t = Target()
    loader.map(t)

    assert len(t.filesystems) == 3
    assert t.filesystems[0].__type__ == "jffs"
    assert t.filesystems[1].__type__ == "squashfs"
    assert t.filesystems[2].__type__ == "jffs"

    assert list(t.fs.listdir("$images$")) == ["u-boot-lzo.img @ 0x6800", "Linux-3.10.14__isvp_pike_1.0__ @ 0x80000"]
