from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.apps.container.podman import PodmanPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_unix_podman(target_unix_users: Target, fs_unix: VirtualFilesystem) -> Target:
    for id, file in [
        ("ae30bde8949f4d4e5b90ad839bbbaffa03db7d9eccbcad7163c34665084d1b70", "httpd"),
        ("4e82f2c6d0ba1a41eacaa5622fcbb9c4e22c9531e6345291a68f6a2219ac9d1a", "nginx"),
        ("bb44c71b8e6c00ba0d4bd483ede69ec32930ca8a30abee4a7f2aadb39cee4988", "debian"),
    ]:
        fs_unix.map_file(
            f"/home/user/.local/share/containers/storage/overlay-containers/{id}/userdata/config.json",
            absolute_path(f"_data/plugins/apps/container/podman/config.json-{file}"),
        )

    fs_unix.map_file(
        "/home/user/.local/share/containers/storage/db.sql",
        absolute_path("_data/plugins/apps/container/podman/db.sql"),
    )

    fs_unix.map_file(
        "/home/user/.local/share/containers/storage/overlay-images/images.json",
        absolute_path("_data/plugins/apps/container/podman/images.json"),
    )

    return target_unix_users


def test_podman_images(target_unix_podman: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can detect Podman images on a target based on an ``images.json`` file.

    Structure of a Podman OCI image on disk::

        $PODMAN/storage/overlay-images/
                                      /images.json
                                      /images.lock
                                      /<HASH>/
                                             /=<BASE64>
                                             /manifest
    """

    target_unix_podman.add_plugin(PodmanPlugin)
    records = list(target_unix_podman.container.images())

    assert sorted([f"{r.name}:{r.tag}" for r in records]) == [
        "docker.io/library/alpine:latest",
        "docker.io/library/debian:latest",
        "docker.io/library/nginx:latest",
        "docker.io/library/ubuntu:latest",
    ]

    assert records[0].name == "docker.io/library/nginx"
    assert records[0].tag == "latest"
    assert records[0].image_id == "4cad75abc83d"
    assert records[0].hash == "4cad75abc83d5ca6ee22053d85850676eaef657ee9d723d7bef61179e1e1e485"
    assert records[0].created == datetime(2025, 2, 5, 21, 27, 16, tzinfo=timezone.utc)
    assert records[0].source == "/home/user/.local/share/containers/storage/overlay-images/images.json"


def test_podman_containers(target_unix_podman: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can detect Podman containers on a target based on a SQLite3 database."""

    target_unix_podman.add_plugin(PodmanPlugin)
    records = list(target_unix_podman.container.containers())

    assert sorted([r.names for r in records]) == [
        "boring_mirzakhani",
        "fervent_proskuriakova",
        "hardcore_khayyam",
        "zen_taussig",
    ]

    assert records[0].container_id == "bb44c71b8e6c00ba0d4bd483ede69ec32930ca8a30abee4a7f2aadb39cee4988"
    assert records[0].image == "docker.io/library/debian:latest"
    assert records[0].image_id == "1fd9a3236e02e50084b18aff689d466641759f4e9e5fee930e194a605081be65"
    assert records[0].command == "bash"
    assert records[0].created == datetime(2025, 4, 9, 11, 37, 41, 694673, tzinfo=timezone.utc)
    assert records[0].running
    assert records[0].pid == 58526
    assert records[0].started == datetime(2025, 4, 9, 11, 37, 42, 68128, tzinfo=timezone.utc)
    assert records[0].finished == datetime(1, 1, 1, tzinfo=timezone.utc)
    assert records[0].ports == []
    assert records[0].names == "hardcore_khayyam"
    assert records[0].volumes == ["/tmp/host-folder:/data"]
    assert records[0].environment == [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "container=podman",
        "TERM=xterm",
    ]
    assert (
        records[0].mount_path
        == "/home/user/.local/share/containers/storage/overlay/f351129587e2bb1da9ba4f03dcd22e1c838cd4f20dcc70e6da72381d2905b913"  # noqa: E501
    )
    assert (
        records[0].config_path
        == "/home/user/.local/share/containers/storage/overlay-containers/bb44c71b8e6c00ba0d4bd483ede69ec32930ca8a30abee4a7f2aadb39cee4988/userdata/config.json"  # noqa: E501
    )
    assert (
        records[0].image_path
        == "/home/user/.local/share/containers/storage/overlay-images/1fd9a3236e02e50084b18aff689d466641759f4e9e5fee930e194a605081be65"  # noqa: E501
    )
    assert records[0].source == "/home/user/.local/share/containers/storage/db.sql"

    assert records[-1].image == "docker.io/library/nginx:latest"
    assert records[-1].command == "nginx -g daemon off;"
    assert records[-1].volumes == ["/tmp/host-folder/host-file.txt:/data/container-file.txt"]
    assert records[-1].ports == ["0.0.0.0:8080->80/tcp"]
