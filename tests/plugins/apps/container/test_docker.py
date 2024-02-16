import datetime
import operator
from io import BytesIO
from pathlib import Path
from typing import Iterator

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.plugins.apps.container.docker import (
    DockerPlugin,
    convert_timestamp,
    find_installs,
    strip_log,
)
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from tests._utils import absolute_path
from tests.conftest import make_mock_target


@pytest.fixture
def target_linux_docker_logs(target_linux: Target, fs_linux: VirtualFilesystem) -> Iterator[Target]:
    docker_containers = absolute_path("_data/plugins/apps/container/docker/logs")
    fs_linux.map_dir("/var/lib/docker/containers", docker_containers)
    yield target_linux


@pytest.fixture
def fs_docker() -> Iterator[TarFilesystem]:
    docker_tar = Path(absolute_path("_data/plugins/apps/container/docker/docker.tgz"))
    fh = docker_tar.open("rb")
    docker_fs = TarFilesystem(fh)
    yield docker_fs


@pytest.fixture
def target_linux_docker(tmp_path: Path, fs_docker: TarFilesystem) -> Iterator[Target]:
    mock_target = next(make_mock_target(tmp_path))
    mock_target._os_plugin = LinuxPlugin

    mock_target.filesystems.add(fs_docker)
    mock_target.fs.mount("/", fs_docker)
    mock_target.apply()
    yield mock_target


def test_docker_plugin_data_roots(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.makedirs("var/lib/docker")
    fs_unix.makedirs("tmp/foo/bar")
    fs_unix.makedirs("tmp/another/docker")
    fs_unix.map_file_fh("/etc/docker/daemon.json", BytesIO(b'{"data-root": "/tmp/foo/bar"}'))
    fs_unix.map_file_fh("/root/.docker/daemon.json", BytesIO(b'{"data-root": "/tmp/another/docker"}'))

    assert [str(p) for p in find_installs(target_unix_users)] == [
        "/var/lib/docker",
        "/tmp/foo/bar",
        "/tmp/another/docker",
    ]


def test_docker_plugin_images(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file(
        "/var/lib/docker/image/overlay2/repositories.json",
        absolute_path("_data/plugins/apps/container/docker/repositories.json"),
    )

    hash = "6b7dfa7e8fdbe18ad425dd965a1049d984f31cf0ad57fa6d5377cca355e65f03"
    fs_unix.map_file(
        f"/var/lib/docker/image/overlay2/imagedb/content/sha256/{hash}",
        absolute_path("_data/plugins/apps/container/docker/image_metadata.json"),
    )

    target_unix_users.add_plugin(DockerPlugin)
    results = list(target_unix_users.docker.images())
    assert len(results) == 2
    assert results[0].tag == "ubuntu:latest"
    assert results[0].hash == f"sha256:{hash}"
    assert results[0].image_id == "6b7dfa7e8fdb"
    assert results[0].created == datetime.datetime(2022, 12, 9, 1, 20, 31, 321639, tzinfo=datetime.timezone.utc)


def test_docker_plugin_containers(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    id = "d3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33f"

    fs_unix.map_file(
        f"/var/lib/docker/containers/{id}/config.v2.json",
        absolute_path("_data/plugins/apps/container/docker/container_running.json"),
    )
    target_unix_users.add_plugin(DockerPlugin)
    results = list(target_unix_users.docker.containers())

    assert len(results) == 1

    result = results[0]

    assert result.container_id == id
    assert result.image == "exampleimage:1.33.7"
    assert result.created == datetime.datetime(2022, 12, 19, 13, 37, 1, 247519, tzinfo=datetime.timezone.utc)
    assert bool(result.running) is True
    assert result.started == datetime.datetime(2022, 12, 19, 13, 37, 1, 247519, tzinfo=datetime.timezone.utc)
    assert result.finished == datetime.datetime(1, 1, 1, 00, 00, 00, 000000, tzinfo=datetime.timezone.utc)
    assert result.ports == str({"1234/tcp": "0.0.0.0:1234", "5678/tcp": "0.0.0.0:5678"})
    assert result.names == "example_container_name"
    assert result.source == f"/var/lib/docker/containers/{id}/config.v2.json"
    assert result.volumes == ["/tmp/test:/test"]


def test_docker_plugin_logs(target_linux_docker_logs: Target) -> None:
    target_linux_docker_logs.add_plugin(DockerPlugin)
    results = list(target_linux_docker_logs.docker.logs())
    results.sort(key=operator.attrgetter("ts"))

    assert len(results) == 288

    # json log driver
    assert results[0].ts == datetime.datetime(2023, 11, 9, 8, 42, 57, 79838, tzinfo=datetime.timezone.utc)
    assert results[0].container == "f988f88e221d97930a665712cf16ab520f7e2c5af395660c145df93aebedf071"
    assert results[0].stream == "stdout"
    assert results[0].message == "/ # "

    # local log driver (protobuf)
    assert results[-1].ts == datetime.datetime(2023, 11, 9, 9, 52, 52, 587579, tzinfo=datetime.timezone.utc)
    assert results[-1].container == "0627aa2d32de2478f4a3e8bb3c655ea7baa1a3463d8cee41263655244fe4717c"
    assert results[-1].stream == "stdout"
    assert results[-1].message == "exit"


def test_docker_plugin_logs_raw(target_linux_docker_logs: Target) -> None:
    target_linux_docker_logs.add_plugin(DockerPlugin)
    results = list(target_linux_docker_logs.docker.logs(raw_messages=True))
    results.sort(key=operator.attrgetter("ts"))

    assert len(results) == 288
    assert results[0].message == "/ # \x1b[6n\r\n"
    assert results[-1].message == "\x1b[?2004l\rexit\r"


def test_docker_plugin_timestamps() -> None:
    # Should not alter already correct timestamps
    assert convert_timestamp("2022-12-19T13:37:00.123456") == "2022-12-19T13:37:00.123456"
    assert convert_timestamp("2022-12-19T13:37:00.123456Z") == "2022-12-19T13:37:00.123456Z"

    # Should convert nanosecond timestamps to microsecond timestamps
    assert convert_timestamp("2022-12-19T13:37:00.123456789Z") == "2022-12-19T13:37:00.123456Z"
    assert convert_timestamp("2022-12-19T13:37:00.12345678Z") == "2022-12-19T13:37:00.123456Z"
    assert convert_timestamp("2022-12-19T13:37:00.123456789+01:00") == "2022-12-19T13:37:00.123456+01:00"


def test_backspace_interpretation() -> None:
    # Should 'execute' backspaces found in input
    input = (
        '~ # \x1b[6necho \'\x08\x1b[J"ths \x08\x1b[J\x08\x1b[Js \x08\x1b[J\x08\x1b[Jis is a secret!" > secret.txt\r\n'
    )
    assert strip_log(input, exc_backspace=True) == '~ # echo "this is a secret!" > secret.txt'
