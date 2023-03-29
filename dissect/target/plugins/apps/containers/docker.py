import json
import re
from typing import Iterator

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

DockerContainerRecord = TargetRecordDescriptor(
    "apps/containers/docker/container",
    [
        ("string", "container_id"),
        ("string", "image"),
        ("string", "command"),
        ("datetime", "created"),
        ("string", "running"),
        ("varint", "pid"),
        ("datetime", "started"),
        ("datetime", "finished"),
        ("string", "ports"),
        ("string", "names"),
        ("stringlist", "volumes"),
        ("string", "source"),
    ],
)

DockerImageRecord = TargetRecordDescriptor(
    "apps/containers/docker/image",
    [
        ("string", "name"),
        ("string", "tag"),
        ("string", "image_id"),
        ("string", "hash"),
        ("datetime", "created"),
    ],
)

DOCKER_NS_REGEX = re.compile(r"\.(?P<nanoseconds>\d{7,})(?P<postfix>Z|\+\d{2}:\d{2})")


class DockerPlugin(Plugin):
    """
    References:
        - https://didactic-security.com/resources/docker-forensics.pdf
        - https://didactic-security.com/resources/docker-forensics-cheatsheet.pdf
        - https://github.com/google/docker-explorer
    """

    __namespace__ = "docker"

    DOCKER_PATH = "/var/lib/docker"

    def check_compatible(self) -> bool:
        return self.target.fs.path(self.DOCKER_PATH).exists()

    @export(record=DockerImageRecord)
    def images(self) -> Iterator[DockerImageRecord]:
        """Returns any pulled docker images on the target system."""

        images_path = f"{self.DOCKER_PATH}/image/overlay2/repositories.json"

        if (fp := self.target.fs.path(images_path)).exists():
            repositories = json.loads(fp.read_text()).get("Repositories")
        else:
            self.target.log.debug(f"No docker images found, file {images_path} does not exist.")
            return

        for name, tags in repositories.items():
            for tag, hash in tags.items():
                image_metadata_path = f"{self.DOCKER_PATH}/image/overlay2/imagedb/content/sha256/{hash.split(':')[-1]}"
                created = None

                if (fp := self.target.fs.path(image_metadata_path)).exists():
                    image_metadata = json.loads(fp.read_text())
                    created = _convert_timestamp(image_metadata.get("created"))

                yield DockerImageRecord(
                    name=name,
                    tag=tag,
                    image_id=_hash_to_image_id(hash),
                    created=created,
                    hash=hash,
                    _target=self.target,
                )

    @export(record=DockerContainerRecord)
    def containers(self) -> Iterator[DockerContainerRecord]:
        """Returns any docker containers present on the target system."""

        containers_path = f"{self.DOCKER_PATH}/containers"
        for container in self.target.fs.path(containers_path).iterdir():
            if (fp := self.target.fs.path(f"{container}/config.v2.json")).exists():
                config = json.loads(fp.read_text())

                if config.get("State").get("Running"):
                    ports = config.get("NetworkSettings").get("Ports", {})
                    pid = config.get("Pid")
                else:
                    ports = config.get("Config").get("ExposedPorts", {})
                    pid = False

                volumes = []
                if mount_points := config.get("MountPoints"):
                    for mp in mount_points:
                        mount_point = mount_points[mp]
                        volumes.append(f"{mount_point.get('Source')}:{mount_point.get('Destination')}")

                yield DockerContainerRecord(
                    container_id=config.get("ID"),
                    image=config.get("Config").get("Image"),
                    command=config.get("Config").get("Cmd"),
                    created=_convert_timestamp(config.get("Created")),
                    running=config.get("State").get("Running"),
                    pid=pid,
                    started=_convert_timestamp(config.get("State").get("StartedAt")),
                    finished=_convert_timestamp(config.get("State").get("FinishedAt")),
                    ports=_convert_ports(ports),
                    names=config.get("Name").replace("/", "", 1),
                    volumes=volumes,
                    source=fp,
                    _target=self.target,
                )


def _convert_timestamp(timestamp: str) -> str:
    """
    Docker sometimes uses (unpadded) 9 digit nanosecond precision
    in their timestamp logs, eg. "2022-12-19T13:37:00.123456789Z".

    Python has no native %n nanosecond strptime directive, so we
    strip the last three digits from the timestamp to force
    compatbility with the 6 digit %f microsecond directive.
    """

    timestamp_nanoseconds_plus_postfix = timestamp[19:]
    match = DOCKER_NS_REGEX.match(timestamp_nanoseconds_plus_postfix)

    # Timestamp does not have nanoseconds if there is no match.
    if not match:
        return timestamp

    # Take the first six digits and reconstruct the timestamp.
    match = match.groupdict()
    microseconds = match["nanoseconds"][:6]
    return f"{timestamp[:19]}.{microseconds}{match['postfix']}"


def _convert_ports(ports: dict) -> dict:
    """
    Depending on the state of the container (turned on or off) we
    can salvage forwarded ports for the container in different
    parts of the config.v2.json file.

    This function attempts to be agnostic and deals with
    "Ports" lists and "ExposedPorts" dicts.

    NOTE: This function makes a couple of assumptions and ignores
    ipv6 assignments. Feel free to improve this helper function.
    """

    fports = {}
    for key, value in ports.items():
        if isinstance(value, list):
            # NOTE: We ignore IPv6 assignments here.
            fports[key] = f"{value[0]['HostIp']}:{value[0]['HostPort']}"
        elif isinstance(value, dict):
            # NOTE: We make the assumption the default broadcast ip 0.0.0.0 was used.
            fports[key] = f"0.0.0.0:{key.split('/')[0]}"

    return fports


def _hash_to_image_id(hash: str) -> str:
    return hash.split(":")[-1][:12]
