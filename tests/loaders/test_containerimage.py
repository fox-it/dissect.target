from pathlib import Path

from dissect.target.loaders.tar import TarLoader
from dissect.target.target import Target
from tests._utils import absolute_path


def test_container_image_filesystem_docker(target_bare: Target) -> None:
    """Test if we map a Docker image correctly."""

    # Uses TarLoader and TarSubLoader functionality.
    path = Path(absolute_path("_data/loaders/containerimage/alpine-docker.tar"))
    assert TarLoader.detect(path)
    loader = TarLoader(path)
    loader.map(target_bare)
    target_bare.apply()

    assert loader.subloader.name == "alpine:latest"
    assert loader.subloader.layers == ["blobs/sha256/a0904247e36a7726c03c71ee48f3e64462021c88dafeb13f37fdaf613b27f11c"]
    assert loader.subloader.config["created"] == "2025-01-08T12:07:30Z"

    assert len(target_bare.filesystems) == 1
    assert len(target_bare.filesystems[0].layers) == 3

    assert sorted(list(map(str, target_bare.fs.path("/").iterdir()))) == [
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


def test_container_image_filesystem_oci_podman(target_bare: Target) -> None:
    """Test if we map a Podman OCI image correctly."""

    path = Path(absolute_path("_data/loaders/containerimage/alpine-oci.tar"))
    assert TarLoader.detect(path)

    loader = TarLoader(path)
    loader.map(target_bare)
    target_bare.apply()

    assert loader.subloader.name == "docker.io/library/alpine:latest"
    assert loader.subloader.layers == ["08000c18d16dadf9553d747a58cf44023423a9ab010aab96cf263d2216b8b350.tar"]
    assert loader.subloader.manifest == {
        "Config": "aded1e1a5b3705116fa0a92ba074a5e0b0031647d9c315983ccba2ee5428ec8b.json",
        "RepoTags": ["docker.io/library/alpine:latest"],
        "Layers": ["08000c18d16dadf9553d747a58cf44023423a9ab010aab96cf263d2216b8b350.tar"],
    }

    assert loader.subloader.config == {
        "architecture": "amd64",
        "config": {
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "Cmd": ["/bin/sh"],
            "WorkingDir": "/",
        },
        "created": "2025-02-14T03:28:36Z",
        "history": [
            {
                "created": "2025-02-14T03:28:36Z",
                "created_by": "ADD alpine-minirootfs-3.21.3-x86_64.tar.gz / # buildkit",
                "comment": "buildkit.dockerfile.v0",
            },
            {
                "created": "2025-02-14T03:28:36Z",
                "created_by": 'CMD ["/bin/sh"]',
                "comment": "buildkit.dockerfile.v0",
                "empty_layer": True,
            },
        ],
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:08000c18d16dadf9553d747a58cf44023423a9ab010aab96cf263d2216b8b350"],
        },
    }

    assert sorted(list(map(str, target_bare.fs.path("/").iterdir()))) == [
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
