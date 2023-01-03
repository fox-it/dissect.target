"""
    @classification UNCLASSIFIED
    @author JSCU CNI
"""

from datetime import datetime

from dissect.target.plugins.os.unix.docker import DockerPlugin

from ._utils import absolute_path


def test_docker_plugin_containers(target_unix_users, fs_unix):
    """
    Test docker container config.v2.json example.
    """

    id = "d3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33f"

    fs_unix.map_file(
        f"/var/lib/docker/containers/{id}/config.v2.json",
        absolute_path("data/unix-logs/docker/container_running.json"),
    )
    target_unix_users.add_plugin(DockerPlugin)
    results = list(target_unix_users.docker.containers())

    assert len(results) == 1

    result = results[0]

    assert result.container_id == id
    assert result.image == "exampleimage:1.33.7"
    assert result.created == datetime.strptime("2022-12-19T13:37:01.247519+00:00", "%Y-%m-%dT%H:%M:%S.%f%z")
    assert bool(result.running) is True
    assert result.started == datetime.strptime("2022-12-19T13:37:01.247519+00:00", "%Y-%m-%dT%H:%M:%S.%f%z")
    assert result.finished == datetime(1970, 1, 1, 00, 00, 00)
    assert result.ports == str({"1234/tcp": "0.0.0.0:1234", "5678/tcp": "0.0.0.0:5678"})
    assert result.names == "example_container_name"
    assert result.source == f"/var/lib/docker/containers/{id}/config.v2.json"
