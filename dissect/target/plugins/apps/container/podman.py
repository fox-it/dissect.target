from __future__ import annotations

import json
from enum import Enum
from typing import TYPE_CHECKING

from dissect.sql import Error as SQLError
from dissect.sql import SQLite3

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.container.container import (
    COMMON_CONTAINER_FIELDS,
    COMMON_IMAGE_FIELDS,
    COMMON_LOG_FIELDS,
    ContainerPlugin,
)
from dissect.target.plugins.apps.container.docker import hash_to_image_id

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target

PodmanImageRecord = TargetRecordDescriptor(
    "apps/containers/podman/image",
    COMMON_IMAGE_FIELDS,
)

PodmanContainerRecord = TargetRecordDescriptor(
    "apps/containers/podman/container",
    COMMON_CONTAINER_FIELDS,
)

PodmanLogRecord = TargetRecordDescriptor(
    "apps/containers/podman/log",
    COMMON_LOG_FIELDS,
)


class ContainerState(Enum):
    """Enum of possible Container states.

    Resources:
        - https://github.com/containers/podman/blob/v4.9/libpod/define/containerstate.go
    """

    NONE = None
    UNKNOWN = 0
    CONFIGURED = 1
    CREATED = 2
    RUNNING = 3
    STOPPED = 4
    PAUSED = 5
    EXITED = 6
    REMOVING = 7
    STOPPING = 8


class PodmanPlugin(ContainerPlugin):
    """Parse Podman artefacts.

    References:
        - https://docs.podman.io/en/latest/_static/api.html
    """

    __namespace__ = "podman"

    SYSTEM_PATHS = (
        # Linux
        "/var/lib/containers",
        # Windows
        "sysvol/ProgramData/containers",
        "sysvol/Program Files/RedHat/Podman/containers",
    )

    USER_PATHS = (
        # Linux and Windows
        ".local/share/containers",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.installs = set(self.find_installs())

    def find_installs(self) -> Iterator[tuple[Path, UserDetails | None]]:
        for path in self.SYSTEM_PATHS:
            if (dir := self.target.fs.path(path)).exists():
                yield dir, None

        for user_details in self.target.user_details.all_with_home():
            for path in self.USER_PATHS:
                if (dir := user_details.home_path.joinpath(path)).exists():
                    yield dir, user_details

    def check_compatible(self) -> None:
        if not self.installs:
            raise UnsupportedPluginError("No Podman install folders found on target")

    @export(record=PodmanImageRecord)
    def images(self) -> Iterator[PodmanImageRecord]:
        """Yield any pulled Podman images on the target system."""
        for dir, _ in self.installs:
            images_json = dir.joinpath("storage/overlay-images/images.json")

            if not images_json.exists():
                self.target.log.debug("No Podman images found, file not found: %s", images_json)
                continue

            try:
                images = json.loads(images_json.read_text()) or []
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                self.target.log.warning("Unable to parse JSON in: %s", images_json)
                self.target.log.debug("", exc_info=e)
                continue

            for image in images:
                name = None
                tag = None

                if image_name := image.get("names", [None])[0]:
                    name, _, tag = image_name.rpartition(":")

                # TODO: when was the image pulled? It is not `created`.
                yield PodmanImageRecord(
                    name=name,
                    tag=tag,
                    image_id=hash_to_image_id(image.get("id")),
                    created=image.get("created"),
                    hash=image.get("id"),
                    source=images_json,
                    _target=self.target,
                )

    @export(record=PodmanContainerRecord)
    def containers(self, save: str | None = None, compress: bool | None = None) -> Iterator[PodmanContainerRecord]:
        """Yield any Podman containers on the target system.

        Uses the ``$PODMAN/storage/db.sql`` SQLite3 database and ``$PODMAN/storage/overlay-containers`` folder.
        Does not (yet) support legacy BoltDB Podman databases.
        """
        for dir, _ in self.installs:
            if (db_path := dir.joinpath("storage/db.sql")).exists():
                yield from self._find_containers_sqlite(db_path)

    def _find_containers_sqlite(self, db_path: Path) -> Iterator:
        """Find Podman containers from existing ``db.sql``.

        Gets info from the ``ContainerConfig`` and ``ContainerState`` tables.
        """

        try:
            db = SQLite3(db_path.open("rb"))
        except (ValueError, SQLError) as e:
            self.target.log.warning("Unable to read Podman database %s: %s", db_path, e)
            self.target.log.debug("", exc_info=e)
            return

        tables = [t.name for t in db.tables()]
        containers = {}

        for table in ["ContainerConfig", "ContainerState"]:
            if table not in tables:
                continue

            for row in db.table(table):
                containers.setdefault(row.ID, {})
                containers[row.ID].update(json.loads(row.JSON))

        for container_id, container in containers.items():
            volumes = []
            for mount_point in container.get("spec", {}).get("mounts", []):
                if mount_point.get("type") == "bind":
                    volumes.append(f"{mount_point.get('source')}:{mount_point.get('destination')}")  # noqa: PERF401

            # $PODMAN/storage/overlay-containers/<ID>/userdata/config.json -> `.root.path` contains the root folder,
            # this does not seem to be stored in the database at all so we have to resort to loading the `config.json`.
            try:
                config_path = db_path.parent.joinpath("overlay-containers", container_id, "userdata", "config.json")
                config = json.loads(config_path.read_text())
                mount_path = config.get("root", {}).get("path")
                if not mount_path:
                    raise ValueError(f"No root path found in {config_path}")  # noqa: TRY301
                mount_path = mount_path.replace("/merged", "")

            except Exception as e:
                self.target.log.warning("Unable to determine container mount path for %s: %s", container_id, e)
                config_path = None
                mount_path = None

            yield PodmanContainerRecord(
                container_id=container_id,
                image=container.get("rootfsImageName"),
                image_id=container.get("rootfsImageID"),
                command=" ".join(container.get("command", [])),
                created=container.get("createdTime"),
                running=ContainerState(container.get("state")) == ContainerState.RUNNING,
                pid=container.get("pid"),
                started=container.get("startedTime"),
                finished=container.get("finishedTime"),
                ports=list(convert_ports(container.get("newPortMappings", []))),  # TODO: research "exposedPorts"
                names=container.get("name"),
                volumes=volumes,
                environment=container.get("spec", {}).get("process", {}).get("env", []),
                mount_path=mount_path,
                config_path=config_path,
                image_path=db_path.parent.joinpath("overlay-images", container.get("rootfsImageID"))
                if container.get("rootfsImageID")
                else None,
                source=db_path,
                _target=self.target,
            )

    @export(record=PodmanLogRecord)
    def logs(self) -> Iterator[PodmanLogRecord]:
        """Returns log files (stdout/stderr) from Podman containers.

        Podman is configured by default to log towards ``syslog`` or ``journald``.
        This function parses non-default ``k8s-file`` and ``json-file`` log driver settings.

        Resources:
            - https://docs.podman.io/en/latest/markdown/podman-create.1.html#log-driver-driver
        """


def convert_ports(ports: dict[str, list | dict]) -> Iterator[str]:
    for p in ports:
        yield (
            f"{p.get('host_ip') or '0.0.0.0'}:{p.get('host_port')}->"
            f"{p.get('container_port')}/{p.get('protocol', 'tcp')}"
        )
