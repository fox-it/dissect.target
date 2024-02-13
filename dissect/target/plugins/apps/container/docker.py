import json
import logging
from pathlib import Path
from typing import Iterator, Optional

from dissect.util import ts

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.docker import (
    c_local,
    convert_ports,
    convert_timestamp,
    hash_to_image_id,
    strip_log,
)
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export
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


def get_data_path(path: Path) -> Optional[str]:
    """Returns the configured Docker daemon data-root path."""
    try:
        config = json.loads(path.open("rt").read())
    except json.JSONDecodeError as e:
        log.warning("Could not read JSON file '%s'", path)
        log.debug(exc_info=e)

    return config.get("data-root")


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
    ]

    user_config_paths = [
        # Docker Desktop (macOS/Windows/Linux)
        ".docker/daemon.json",
    ]

    if (default_root := target.fs.path("/var/lib/docker")).exists():
        yield default_root

    for path in default_config_paths:
        if (config_file := target.fs.path(path)).exists():
            if (data_root_path := target.fs.path(get_data_path(config_file))).exists():
                yield data_root_path

    for path in user_config_paths:
        for user_details in target.user_details.all_with_home():
            if (config_file := user_details.home_path.joinpath(path)).exists():
                if (data_root_path := target.fs.path(get_data_path(config_file))).exists():
                    yield data_root_path


class DockerPlugin(Plugin):
    """Parse Docker Daemon artefacts.

    References:
        - https://didactic-security.com/resources/docker-forensics.pdf
        - https://didactic-security.com/resources/docker-forensics-cheatsheet.pdf
        - https://github.com/google/docker-explorer
    """

    __namespace__ = "docker"

    def __init__(self, target: Target):
        super().__init__(target)
        self.installs = set(find_installs(target))

    def check_compatible(self) -> None:
        if not self.installs:
            raise UnsupportedPluginError("No Docker install(s) found")

    @export(record=DockerImageRecord)
    def images(self) -> Iterator[DockerImageRecord]:
        """Returns any pulled docker images on the target system."""

        for data_root in self.installs:
            images_path = data_root.joinpath("image/overlay2/repositories.json")

            if images_path.exists():
                repositories = json.loads(images_path.read_text()).get("Repositories")
            else:
                self.target.log.debug("No docker images found, file %s does not exist.", images_path)
                return

            for name, tags in repositories.items():
                for tag, hash in tags.items():
                    image_metadata_path = data_root.joinpath(
                        "image/overlay2/imagedb/content/sha256/", hash.split(":")[-1]
                    )
                    created = None

                    if image_metadata_path.exists():
                        image_metadata = json.loads(image_metadata_path.read_text())
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
            for config_path in data_root.joinpath("containers").glob("**/config.v2.json"):
                config = json.loads(config_path.read_text())
                running = config.get("State").get("Running")
                if running:
                    ports = config.get("NetworkSettings").get("Ports", {})
                    pid = config.get("Pid")
                else:
                    ports = config.get("Config").get("ExposedPorts", {})
                    pid = None
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
                    running=running,
                    pid=pid,
                    started=convert_timestamp(config.get("State").get("StartedAt")),
                    finished=convert_timestamp(config.get("State").get("FinishedAt")),
                    ports=convert_ports(ports),
                    names=config.get("Name").replace("/", "", 1),
                    volumes=volumes,
                    source=config_path,
                    _target=self.target,
                )

    @export(record=DockerLogRecord)
    @arg(
        "--raw-messages",
        action="store_true",
        help="preserve ANSI escape sequences and trailing newlines from log messages",
    )
    @arg(
        "--remove-backspaces",
        action="store_true",
        help="alter messages by removing ASCII backspaces and the corresponding characters",
    )
    def logs(self, raw_messages: bool = False, remove_backspaces: bool = False) -> Iterator[DockerLogRecord]:
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
            containers_path = data_root.joinpath("containers")

            for log_file in containers_path.glob(("**/*.log*")):
                container = log_file.parent

                # json log driver
                if "-json.log" in log_file.name:
                    for log_entry in self._parse_json_log(log_file):
                        yield DockerLogRecord(
                            ts=log_entry.get("time"),
                            container=container.name,  # container hash
                            stream=log_entry.get("stream"),
                            message=log_entry.get("log")
                            if raw_messages
                            else strip_log(log_entry.get("log"), remove_backspaces),
                            _target=self.target,
                        )

                # local log driver
                else:
                    for log_entry in self._parse_local_log(log_file):
                        yield DockerLogRecord(
                            ts=ts.from_unix_us(log_entry.ts // 1000),
                            container=container.parent.name,  # container hash
                            stream=log_entry.source,
                            message=log_entry.message
                            if raw_messages
                            else strip_log(log_entry.message, remove_backspaces),
                            _target=self.target,
                        )

    def _parse_local_log(self, path: Path) -> Iterator[c_local.entry]:
        fh = open_decompress(path, "rb")  # can be a .gz file

        while True:
            try:
                entry = c_local.entry(fh)
                if entry.header != entry.footer:
                    self.target.log.warning(
                        "Could not reliably parse log entry at offset %i in file %s."
                        "Entry could be parsed incorrectly. Please report this "
                        "issue as Docker's protobuf could have changed.",
                        fh.tell(),
                        path,
                    )
                yield entry
            except EOFError:
                break

    def _parse_json_log(self, path: Path) -> Iterator[dict]:
        for line in open_decompress(path, "rt"):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                self.target.log.warning("Could not decode JSON line in file %s", path)
                self.target.log.debug("", exc_info=e)
                continue
            yield entry
