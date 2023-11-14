import datetime

from dissect.target.helpers.docker import convert_timestamp
from dissect.target.plugins.apps.container.docker import DockerPlugin
from tests._utils import absolute_path


def test_docker_plugin_images(target_unix_users, fs_unix):
    """Test docker image listing."""

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


def test_docker_plugin_containers(target_unix_users, fs_unix):
    """Test docker container config.v2.json example."""

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


def test_docker_plugin_timestamps():
    """Test the docker convert_timestamp function."""

    # Should not alter already correct timestamps
    assert convert_timestamp("2022-12-19T13:37:00.123456") == "2022-12-19T13:37:00.123456"
    assert convert_timestamp("2022-12-19T13:37:00.123456Z") == "2022-12-19T13:37:00.123456Z"

    # Should convert nanosecond timestamps to microsecond timestamps
    assert convert_timestamp("2022-12-19T13:37:00.123456789Z") == "2022-12-19T13:37:00.123456Z"
    assert convert_timestamp("2022-12-19T13:37:00.12345678Z") == "2022-12-19T13:37:00.123456Z"
    assert convert_timestamp("2022-12-19T13:37:00.123456789+01:00") == "2022-12-19T13:37:00.123456+01:00"


def test_docker_plugin_logs(target_linux_docker_logs):
    target_linux_docker_logs.add_plugin(DockerPlugin)
    results = list(target_linux_docker_logs.docker.logs())

    assert len(results) == 288

    # json log driver
    assert results[40].ts == datetime.datetime(2023, 11, 9, 8, 43, 42, 321404, tzinfo=datetime.timezone.utc)
    assert results[40].container == "f988f88e221d97930a665712cf16ab520f7e2c5af395660c145df93aebedf071"
    assert results[40].stream == "stdout"
    assert (
        results[40].message
        == '~ # \x1b[6necho \'\x08\x1b[J"ths \x08\x1b[J\x08\x1b[Js \x08\x1b[J\x08\x1b[Jis is a secret!" > secret.txt\r\n'  # noqa
    )

    # local log driver (protobuf)
    assert results[-1].ts == datetime.datetime(2023, 11, 9, 9, 52, 52, 587579, tzinfo=datetime.timezone.utc)
    assert results[-1].container == "0627aa2d32de2478f4a3e8bb3c655ea7baa1a3463d8cee41263655244fe4717c"
    assert results[-1].stream == "stdout"
    assert results[-1].message == "\x1b[?2004l\rexit\r"

    # TODO: gz compressed json and local logs
