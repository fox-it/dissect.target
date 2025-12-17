from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest

from dissect.target.loader import Loader
from dissect.target.loader import open as loader_open
from dissect.target.loaders.nscollector import NsCollectorTarSubLoader
from dissect.target.loaders.tar import TarLoader
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
    """Test that we correctly use ``NsCollectorTarSubLoader`` when opening a ``Target``."""
    path = absolute_path("_data/loaders/nscollector/collector_P_10.164.0.3_22Oct2025_11_31.tar.gz")

    target = opener(path)
    assert isinstance(target._loader, TarLoader)
    assert isinstance(target._loader.subloader, NsCollectorTarSubLoader)
    assert target.path == path


def test_compressed_tar(caplog: pytest.LogCaptureFixture) -> None:
    """Test if we map a compressed NetScaler Collector tar image correctly."""
    path = absolute_path("_data/loaders/nscollector/collector_P_10.164.0.3_22Oct2025_11_31.tar.gz")

    with caplog.at_level(logging.WARNING):
        loader = loader_open(path)
        assert isinstance(loader, TarLoader)
        assert "is compressed" in caplog.text

    t = Target()
    loader.map(t)
    assert isinstance(loader.subloader, NsCollectorTarSubLoader)
    assert len(t.filesystems) == 1

    t.apply()
    test_file = t.fs.path("/nsconfig/ns.conf")
    assert test_file.exists()
    assert test_file.is_file()
    assert test_file.open().readline() == b"#NS14.1 Build 51.80\n"
