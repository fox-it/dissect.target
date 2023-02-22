import datetime

from dissect.target.plugins.apps.containers.docker import (
    DockerPlugin,
    _convert_timestamp,
)

from ._utils import absolute_path


def test_docker_plugin_images(target_unix_users, fs_unix):
    """Test docker image listing."""

    fs_unix.map_file(
        "/var/lib/docker/image/overlay2/repositories.json",
        absolute_path("data/apps/containers/docker/repositories.json"),
    )

    hash = "6b7dfa7e8fdbe18ad425dd965a1049d984f31cf0ad57fa6d5377cca355e65f03"
    fs_unix.map_file(
        f"/var/lib/docker/image/overlay2/imagedb/content/sha256/{hash}",
        absolute_path("data/apps/containers/docker/image_metadata.json"),
    )

    target_unix_users.add_plugin(DockerPlugin)
    results = list(target_unix_users.docker.images())
    assert len(results) == 2
    assert results[0].tag == "ubuntu:latest"
    assert results[0].hash == f"sha256:{hash}"
    assert results[0].image_id == "6b7dfa7e8fdb"
    assert results[0].created == datetime.datetime(2022, 12, 9, 1, 20, 31, 321639, tzinfo=datetime.timezone.utc)


def test_docker_plugin_containers(target_unix_users, fs_unix):
    """Test docker container config.v2.json example."""

    id = "d3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33f"

    fs_unix.map_file(
        f"/var/lib/docker/containers/{id}/config.v2.json",
        absolute_path("data/apps/containers/docker/container_running.json"),
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


def test_docker_plugin_timestamps():
    """Test the docker convert_timestamp function."""

    # Should not alter already correct timestamps
    assert _convert_timestamp("2022-12-19T13:37:00.123456") == "2022-12-19T13:37:00.123456"
    assert _convert_timestamp("2022-12-19T13:37:00.123456Z") == "2022-12-19T13:37:00.123456Z"

    # Should convert nanosecond timestamps to microsecond timestamps
    assert _convert_timestamp("2022-12-19T13:37:00.123456789Z") == "2022-12-19T13:37:00.123456Z"
    assert _convert_timestamp("2022-12-19T13:37:00.12345678Z") == "2022-12-19T13:37:00.123456Z"
    assert _convert_timestamp("2022-12-19T13:37:00.123456789+01:00") == "2022-12-19T13:37:00.123456+01:00"
