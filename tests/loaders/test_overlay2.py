from __future__ import annotations

from typing import TYPE_CHECKING, Callable

import pytest

from dissect.target import Target
from dissect.target.loader import open as loader_open
from dissect.target.loaders.overlay2 import Overlay2Loader

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target], target_linux_docker: Target) -> None:
    """Test that we correctly use ``Overlay2Loader`` when opening a ``Target``."""
    for container in [
        "589135d12011921ac6ce69753569da5f206f4bc792a9133727ddae860997ee66",
        "f988f88e221d97930a665712cf16ab520f7e2c5af395660c145df93aebedf071",
    ]:
        path = target_linux_docker.fs.path("/var/lib/docker/image/overlay2/layerdb/mounts").joinpath(container)
        target = opener(path)
        assert isinstance(target._loader, Overlay2Loader)
        assert target.path == path


@pytest.mark.parametrize(
    ("path", "layers", "entries"),
    [
        ("589135d12011921ac6ce69753569da5f206f4bc792a9133727ddae860997ee66", 4, 18),
        ("f988f88e221d97930a665712cf16ab520f7e2c5af395660c145df93aebedf071", 9, 19),
    ],
)
def test_docker(target_linux_docker: Target, path: str, layers: int, entries: int) -> None:
    """Test if we correctly detect and map a Docker container."""
    container = target_linux_docker.fs.path("/var/lib/docker/image/overlay2/layerdb/mounts").joinpath(path)

    loader = loader_open(container)
    assert isinstance(loader, Overlay2Loader)

    t = Target()
    loader.map(t)

    assert len(t.filesystems) == 1

    container_fs = t.filesystems[0]
    assert len(container_fs.layers) == layers
    assert len(list(container_fs.path("/").iterdir())) == entries
