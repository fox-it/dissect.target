from __future__ import annotations

from dissect.target.filesystems.overlay import OverlayFsFilesystem
from dissect.target.loader import open as loader_open
from dissect.target.loaders.overlayfs import OverlayFsLoader
from dissect.target.target import Target
from tests.plugins.apps.container.test_containerd import target_unix_containerd_docker  # noqa: F401


def test_containerd(target_unix_containerd_docker: Target) -> None:  # noqa: F811
    """Test if we correctly detect and map a containerd container.

    We use the layers of a ubuntu base image except most of the base image executables (layer 8) to save space.

    Created using:
        debian:/$ cd /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots
        debian:/$ tar -czvf snapshots.tgz 11 10 9 8/fs/root 8/fs/var 8/fs/home 8/fs/etc 8/fs/boot
    """
    container_id = "5fc9c48c9ee7a72c4e733a19c0388e6d7b26413fd0949f855067bfb8dd2d2181"
    mount_path = target_unix_containerd_docker.fs.path(
        f"/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db/{container_id}"
    )
    assert OverlayFsLoader.detect(mount_path)

    loader = loader_open(mount_path)
    assert isinstance(loader, OverlayFsLoader)

    target = Target()
    loader.map(target)
    target.apply()
    assert len(target.filesystems) == 1
    assert isinstance(target.filesystems[0], OverlayFsFilesystem)  # type: ignore
    assert list(map(str, target.fs.path("/").iterdir())) == [
        "/root",
        "/var",
        "/home",
        "/etc",
        "/boot",
        "/.rock",
        "/.dockerenv",
        "/dev",
    ]

    assert target.fs.path("/root/hello.txt").read_text() == "hello world!\n"
