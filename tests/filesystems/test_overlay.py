from dissect.target import Target
from dissect.target.filesystems.overlay import Overlay2Filesystem


def test_overlay_filesystem_docker_container(target_linux_docker: Target) -> None:
    mount_path = list(target_linux_docker.fs.path("/var/lib/docker/image/overlay2/layerdb/mounts/").iterdir())[0]
    fs = Overlay2Filesystem(mount_path)

    assert fs.__type__ == "overlay2"
    assert len(fs.layers) == 4

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
        ]
    )

    assert [str(p) for p in fs.path("/root").iterdir()] == [
        "/root/secret.txt",
        "/root/file.txt",
        "/root/.ash_history",
    ]

    assert fs.path("/root/secret.txt").open().read() == b"this is a secret!\n"
    assert len([str(p) for p in fs.path("/etc").iterdir()]) == 38

    # test some random symlinks
    assert fs.path("/bin/sh").is_symlink()
    assert fs.path("/bin/sh").resolve() == fs.path("/bin/busybox")
    assert fs.path("/bin/sh").readlink() == fs.path("/bin/busybox")
    assert fs.path("/etc/ssl/cert.pem").resolve() == fs.path("/etc/ssl/certs/ca-certificates.crt")
    assert fs.path("/usr/lib/libcrypto.so.3").resolve() == fs.path("/lib/libcrypto.so.3")
