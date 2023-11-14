import json
import logging
from pathlib import Path
from typing import Iterator

from dissect.util import ts

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.docker import (
    c_local,
    convert_ports,
    convert_timestamp,
    hash_to_image_id,
)
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.target import Target

log = logging.getLogger(__name__)

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


DockerLogRecord = TargetRecordDescriptor(
    "apps/containers/docker/log",
    [
        ("datetime", "ts"),
        ("string", "container"),
        ("string", "stream"),
        ("string", "message"),
    ],
)


def find_installs(target: Target) -> Iterator[Path]:
    """Attempt to find additional configured and existing Docker daemon data-root folders.

    References:
        - https://docs.docker.com/config/daemon/
    """

    default_config_paths = [
        # Linux
        "/etc/docker/daemon.json",
        "/var/snap/docker/current/config/daemon.json",
        # Windows
        "sysvol/ProgramData/docker/config/daemon.json",
        # Docker Desktop (macOS/Windows/Linux)
        "$HOME/.docker/daemon.json",
    ]

    if (default_root := target.fs.path("/var/lib/docker")).exists():
        yield default_root

    for config_path in default_config_paths:
        config_file = target.fs.path(config_path)

        if config_path.startswith("$HOME"):
            for user_details in target.user_details.all_with_home():
                user_config = user_details.home_path.joinpath(config_path.replace("$HOME/", ""))
                if user_config.exists():
                    default_config_paths.append(str(user_config))

        elif config_file.exists():
            try:
                config = json.loads(config_file.open("rt").read())
            except json.JSONDecodeError as e:
                log.warning(f"Could not read JSON file '{config_file}'")
                log.debug(exc_info=e)

            if data_root := config.get("data-root"):
                if (data_root_path := target.fs.path(data_root)).exists():
                    yield data_root_path


class DockerPlugin(Plugin):
    """Parse Docker Daemon artefacts.

    References:
        - https://didactic-security.com/resources/docker-forensics.pdf
        - https://didactic-security.com/resources/docker-forensics-cheatsheet.pdf
        - https://github.com/google/docker-explorer
    """

    __namespace__ = "docker"

    def __init__(self, target) -> None:
        super().__init__(target)
        self.installs = set(find_installs(target))

    def check_compatible(self) -> None:
        if not any(self.installs):
            raise UnsupportedPluginError("No Docker install(s) found.")

    @export(record=DockerImageRecord)
    def images(self) -> Iterator[DockerImageRecord]:
        """Returns any pulled docker images on the target system."""

        for data_root in self.installs:
            images_path = f"{data_root}/image/overlay2/repositories.json"

            if (fp := self.target.fs.path(images_path)).exists():
                repositories = json.loads(fp.read_text()).get("Repositories")
            else:
                self.target.log.debug(f"No docker images found, file {images_path} does not exist.")
                return

            for name, tags in repositories.items():
                for tag, hash in tags.items():
                    image_metadata_path = f"{data_root}/image/overlay2/imagedb/content/sha256/{hash.split(':')[-1]}"
                    created = None

                    if (fp := self.target.fs.path(image_metadata_path)).exists():
                        image_metadata = json.loads(fp.read_text())
                        created = convert_timestamp(image_metadata.get("created"))

                    yield DockerImageRecord(
                        name=name,
                        tag=tag,
                        image_id=hash_to_image_id(hash),
                        created=created,
                        hash=hash,
                        _target=self.target,
                    )

    @export(record=DockerContainerRecord)
    def containers(self) -> Iterator[DockerContainerRecord]:
        """Returns any docker containers present on the target system."""

        for data_root in self.installs:
            containers_path = f"{data_root}/containers"

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
                        created=convert_timestamp(config.get("Created")),
                        running=config.get("State").get("Running"),
                        pid=pid,
                        started=convert_timestamp(config.get("State").get("StartedAt")),
                        finished=convert_timestamp(config.get("State").get("FinishedAt")),
                        ports=convert_ports(ports),
                        names=config.get("Name").replace("/", "", 1),
                        volumes=volumes,
                        source=fp,
                        _target=self.target,
                    )

    @export(record=DockerLogRecord)
    def logs(self) -> Iterator[DockerLogRecord]:
        """Returns log files (stdout/stderr) from Docker containers.

        The default Docker Daemon log driver is ``json-file``, which
        performs no log rotation. Another log driver is ``local`` and
        performs log rotation and compresses log files more efficiently.

        Eventually ``local`` will likely replace ``json-file`` as the
        default log driver.

        Resources:
            - https://docs.docker.com/config/containers/logging/configure/
            - https://docs.docker.com/config/containers/logging/json-file/
            - https://docs.docker.com/config/containers/logging/local/
        """

        for data_root in self.installs:
            containers_path = f"{data_root}/containers"

            for container in self.target.fs.path(containers_path).iterdir():
                # json-file log driver
                for log_file in container.glob(f"{container.name}-json.log*"):
                    for line in open_decompress(log_file, "rt"):
                        try:
                            log_entry = json.loads(line)
                        except json.JSONDecodeError as e:
                            self.target.log.warning(f"Could not decode JSON line in file {log_file}")
                            self.target.log.debug("", exc_info=e)
                            continue

                        yield DockerLogRecord(
                            ts=log_entry.get("time"),
                            container=container.name,
                            stream=log_entry.get("stream"),
                            message=log_entry.get("log"),
                            _target=self.target,
                        )

                # local log driver
                for log_file in container.glob("local-logs/container.log*"):
                    fh = open_decompress(log_file, "rb")
                    pos = 0

                    if not hasattr(fh, "size"):  # for pytest
                        fh.size = len(fh.read())
                        fh.seek(0)

                    while fh.tell() < fh.size:
                        fh.seek(pos)
                        entry = c_local.entry(fh)

                        if entry.header != entry.footer:
                            self.target.log.warning(
                                f"Could not reliably parse log entry at offset {pos}."
                                "Entry could be parsed incorrectly. Please report this "
                                "issue as Docker's protobuf could have changed."
                            )

                        pos += entry.header + 8

                        yield DockerLogRecord(
                            ts=ts.from_unix_us(entry.ts // 1000),
                            container=container.name,
                            stream=entry.source,
                            message=entry.message,
                            _target=self.target,
                        )
