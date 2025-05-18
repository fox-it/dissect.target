from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.overlay import Overlay2Filesystem

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_overlay_filesystem_docker_container(target_linux_docker: Target) -> None:
    mount_path = target_linux_docker.fs.path(
        "/var/lib/docker/image/overlay2/layerdb/mounts/f988f88e221d97930a665712cf16ab520f7e2c5af395660c145df93aebedf071"
    )
    fs = Overlay2Filesystem(mount_path)

    assert fs.__type__ == "overlay2"
    assert len(fs.layers) == 9

    assert sorted([str(p) for p in fs.path("/").iterdir()]) == sorted(
        [
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
            "/container",
        ]
    )

    assert sorted([str(p) for p in fs.path("/root").iterdir()]) == [
        "/root/.ash_history",
        "/root/file.txt",
        "/root/secret.txt",
    ]

    assert fs.path("/root/secret.txt").open().read() == b"this is a secret!\n"
    assert len([str(p) for p in fs.path("/etc").iterdir()]) == 38

    # test some random symlinks
    assert fs.path("/bin/sh").is_symlink()
    assert fs.path("/bin/sh").resolve() == fs.path("/bin/busybox")
    assert fs.path("/bin/sh").readlink() == fs.path("/bin/busybox")
    assert fs.path("/etc/ssl/cert.pem").resolve() == fs.path("/etc/ssl/certs/ca-certificates.crt")
    assert fs.path("/usr/lib/libcrypto.so.3").resolve() == fs.path("/lib/libcrypto.so.3")

    # test if standard mounts were correctly added
    assert fs.path("/etc/hostname").exists()
    assert fs.path("/etc/hostname").is_file()
    assert fs.path("/etc/hostname").read_text() == "f988f88e221d\n"
    assert fs.path("/etc/hosts").exists()
    assert fs.path("/etc/resolv.conf").exists()

    # test if custom mounts were correctly added
    assert fs.path("/container/file.txt").exists()
    assert fs.path("/container/file.txt").is_file()
    assert fs.path("/container/file.txt").read_text() == "this is a mounted file!\n"
    assert fs.path("/container/folder").exists()
    assert fs.path("/container/folder").is_dir()
    assert fs.path("/container/folder/some-file.txt").exists()
    assert fs.path("/container/folder/some-file.txt").is_file()
