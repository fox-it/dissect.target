from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loaders.overlay import Overlay2Loader
from tests.plugins.apps.container.test_docker import (  # noqa: F401
    fs_docker,
    target_linux_docker,
)


def test_overlay_loader_docker_container(
    target_linux_docker: Target, fs_docker: VirtualFilesystem  # noqa: F811
) -> None:
    for container in target_linux_docker.fs.path("/var/lib/docker/image/overlay2/layerdb/mounts/").iterdir():
        assert Overlay2Loader.detect(container)
        loader = Overlay2Loader(container)
        loader.map(target_linux_docker)

    assert len(target_linux_docker.filesystems) == 4

    container_fs = target_linux_docker.filesystems[1]
    for layer in container_fs.mounts["/"]:
        assert layer.__type__ == "overlay2"

    assert sorted([str(p) for p in container_fs.path("/").iterdir()]) == sorted([
        "/home",
        "/root",
        "/media",
        "/var",
        "/tmp",
        "/mnt",
        "/bin",
        "/sys",
        "/lib",
        "/proc",
        "/dev",
        "/etc",
        "/run",
        "/sbin",
        "/opt",
        "/usr",
        "/srv",
        "/.dockerenv",
    ])

    assert [str(p) for p in container_fs.path("/root").iterdir()] == [
        "/root/secret.txt",
        "/root/file.txt",
        "/root/.ash_history",
    ]

    assert container_fs.path("/root/secret.txt").open().read() == b"this is a secret!\n"
    assert len([str(p) for p in container_fs.path("/etc").iterdir()]) == 38

    # test some random symlinks
    assert container_fs.path("/bin/sh").is_symlink()
    assert container_fs.path("/bin/sh").resolve() == container_fs.path("/bin/busybox")
    assert container_fs.path("/bin/sh").readlink() == container_fs.path("/bin/busybox")
    assert container_fs.path("/etc/ssl/cert.pem").resolve() == container_fs.path("/etc/ssl/certs/ca-certificates.crt")
    assert container_fs.path("/usr/lib/libcrypto.so.3").resolve() == container_fs.path("/lib/libcrypto.so.3")
