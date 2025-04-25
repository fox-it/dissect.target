from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.loaders.tar import TarLoader
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_container_image_filesystem(target_bare: Target) -> None:
    """Test if we map a container image correctly."""

    # Uses TarLoader and TarSubLoader functionality.
    path = Path(absolute_path("_data/loaders/containerimage/alpine.tar"))
    assert TarLoader.detect(path)
    loader = TarLoader(path)
    loader.map(target_bare)
    target_bare.apply()

    assert loader.subloader.name == "alpine:latest"
    assert loader.subloader.manifest["Layers"] == [
        "blobs/sha256/a0904247e36a7726c03c71ee48f3e64462021c88dafeb13f37fdaf613b27f11c"
    ]
    assert loader.subloader.config["created"] == "2025-01-08T12:07:30Z"

    assert len(target_bare.filesystems) == 1
    assert len(target_bare.filesystems[0].layers) == 3

    assert sorted(map(str, target_bare.fs.path("/").iterdir())) == [
        "/$fs$",
        "/bin",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/media",
        "/mnt",
        "/opt",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/srv",
        "/sys",
        "/tmp",
        "/usr",
        "/var",
    ]
