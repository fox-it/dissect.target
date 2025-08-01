from __future__ import annotations

from io import BytesIO

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import open as loader_open
from dissect.target.loaders.overlay import OverlayLoader
from dissect.target.target import Target

BASE_PATH = "/home/user/.local/share/containers/storage/overlay/f351129587e2bb1da9ba4f03dcd22e1c838cd4f20dcc70e6da72381d2905b913"  # noqa: E501


@pytest.fixture
def mock_oci_podman_fs() -> VirtualFilesystem:
    vfs = VirtualFilesystem()

    vfs.makedirs(BASE_PATH)
    vfs.makedirs(f"{BASE_PATH}/diff")
    vfs.makedirs(f"{BASE_PATH}/work")
    vfs.map_file_fh(f"{BASE_PATH}/link", BytesIO())
    vfs.map_file_fh(f"{BASE_PATH}/lower", BytesIO())

    vfs.map_file_fh(f"{BASE_PATH}/diff/test.txt", BytesIO(b"example"))

    return vfs


def test_target_open(mock_oci_podman_fs: VirtualFilesystem) -> None:
    """Test that we correctly use ``OverlayLoader`` when opening a ``Target``."""
    path = mock_oci_podman_fs.path(BASE_PATH)
    for target in (Target.open(path), next(Target.open_all(path), None)):
        assert target is not None
        assert isinstance(target._loader, OverlayLoader)
        assert target.path == path


def test_oci_podman(mock_oci_podman_fs: VirtualFilesystem) -> None:
    """Test if we correctly detect and map a Podman OCI container."""
    loader = loader_open(mock_oci_podman_fs.path(BASE_PATH))
    assert isinstance(loader, OverlayLoader)

    t = Target()
    loader.map(t)
    t.apply()

    assert len(t.filesystems) == 1
    assert list(map(str, t.fs.path("/").iterdir())) == ["/test.txt"]
