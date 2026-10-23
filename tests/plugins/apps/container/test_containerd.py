from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.apps.container.containerd import ContainerdPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_unix_containerd_docker(target_unix: Target, fs_unix: VirtualFilesystem) -> Target:
    fs_unix.map_file(
        "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db",
        absolute_path("_data/plugins/apps/container/containerd/docker/io.containerd.metadata.v1.bolt/meta.db"),
    )
    fs_unix.map_file(
        "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/metadata.db",
        absolute_path(
            "_data/plugins/apps/container/containerd/docker/io.containerd.snapshotter.v1.overlayfs/metadata.db"
        ),
    )
    fs_unix.map_dir_from_tar(
        "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots",
        absolute_path(
            "_data/plugins/apps/container/containerd/docker/io.containerd.snapshotter.v1.overlayfs/snapshots.tgz"
        ),
    )
    target_unix.add_plugin(ContainerdPlugin)
    return target_unix


def test_containerd_docker_images(target_unix_containerd_docker: Target) -> None:
    """Test if we can parse containerd docker images."""
    records = list(target_unix_containerd_docker.containerd.images())
    assert len(records) == 2

    assert records[0].name == "docker.io/library/hello-world"
    assert records[0].tag == "latest"
    assert records[0].image_id == "5dd0d3e6e255"
    assert records[0].hash == "sha256:5dd0d3e6e255913fc30f90b9f2b1d359cc2cbdb48090cc4b65f1676e203243cc"
    assert records[0].created == datetime(2026, 8, 27, 10, 0, 50, 115034, tzinfo=timezone.utc)
    assert records[0].source == "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"

    assert records[1].name == "docker.io/library/ubuntu"
    assert records[1].tag == "latest"
    assert records[1].image_id == "2260313b31c8"
    assert records[1].hash == "sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b"
    assert records[1].created == datetime(2026, 8, 27, 11, 53, 4, 382512, tzinfo=timezone.utc)
    assert records[1].source == "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"


def test_containerd_docker_containers(target_unix_containerd_docker: Target) -> None:
    """Test if we can parse (running) containerd docker containers."""
    records = list(target_unix_containerd_docker.containerd.containers())
    assert len(records) == 1

    assert records[0].container_id == "5fc9c48c9ee7a72c4e733a19c0388e6d7b26413fd0949f855067bfb8dd2d2181"
    assert records[0].image == "docker.io/library/ubuntu:latest"
    assert records[0].image_id is None
    assert records[0].command is None
    assert records[0].created == datetime(2026, 8, 27, 12, 17, 17, 190524, tzinfo=timezone.utc)
    assert records[0].running is None
    assert records[0].pid is None
    assert records[0].started is None
    assert records[0].finished is None
    assert records[0].ports == []
    assert records[0].name is None
    assert records[0].volumes == [
        "/var/lib/docker/containers/5fc9c48c9ee7a72c4e733a19c0388e6d7b26413fd0949f855067bfb8dd2d2181/resolv.conf:/etc/resolv.conf",
        "/var/lib/docker/containers/5fc9c48c9ee7a72c4e733a19c0388e6d7b26413fd0949f855067bfb8dd2d2181/hostname:/etc/hostname",
        "/var/lib/docker/containers/5fc9c48c9ee7a72c4e733a19c0388e6d7b26413fd0949f855067bfb8dd2d2181/hosts:/etc/hosts",
    ]
    assert records[0].environment == [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOSTNAME=5fc9c48c9ee7",
        "TERM=xterm",
    ]
    assert (
        records[0].mount_path
        == "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db/5fc9c48c9ee7a72c4e733a19c0388e6d7b26413fd0949f855067bfb8dd2d2181"  # noqa: E501
    )
    assert records[0].config_path is None
    assert records[0].image_path is None
    assert records[0].source == "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"
