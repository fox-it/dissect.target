from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.loaders.overlay import OverlayLoader

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_overlay_loader_oci_podman(target_bare: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we correctly detect and map a Podman OCI container."""

    base = "/home/user/.local/share/containers/storage/overlay/f351129587e2bb1da9ba4f03dcd22e1c838cd4f20dcc70e6da72381d2905b913"  # noqa: E501
    fs_unix.makedirs(base)
    fs_unix.makedirs(f"{base}/diff")
    fs_unix.makedirs(f"{base}/work")
    fs_unix.map_file_fh(f"{base}/link", BytesIO(b""))
    fs_unix.map_file_fh(f"{base}/lower", BytesIO(b""))

    fs_unix.map_file_fh(f"{base}/diff/test.txt", BytesIO(b"example"))

    assert OverlayLoader.detect(fs_unix.path(base))

    loader = OverlayLoader(fs_unix.path(base))
    loader.map(target_bare)
    target_bare.apply()

    assert len(target_bare.filesystems) == 1

    assert list(map(str, target_bare.fs.path("/").iterdir())) == ["/test.txt"]
