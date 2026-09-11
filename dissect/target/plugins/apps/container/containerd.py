from __future__ import annotations

import re
from typing import TYPE_CHECKING, TextIO

from dissect.database.bbolt import Bbolt
from dissect.util.ts import golangtimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.logging import get_logger
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.typeurl import unmarshal_any_json
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

    from dissect.target.target import Target


log = get_logger(__name__)


ContainerdImageRecord = TargetRecordDescriptor(
    "application/container/containerd/image",
    COMMON_IMAGE_FIELDS,
)

ContainerdContainerRecord = TargetRecordDescriptor(
    "application/container/containerd/container",
    COMMON_CONTAINER_FIELDS,
)


ContainerdLogRecord = TargetRecordDescriptor(
    "application/container/containerd/log",
    COMMON_LOG_FIELDS,
)


RE_CTR_LOG = re.compile(
    r"""
        ^
        (?P<ts>\d{4}-\d{2}-\d{2}T\d{2}\:\d{2}\:\d{2}\.\d{9}(Z|([\+\-]\d{2}\:\d{2})))
        \s
        (?P<stream>(stderr|stdout))
        \s
        (?P<type>\S)
        \s
        (?P<message>.*)
        $
    """,
    re.VERBOSE,
)


class ContainerdPlugin(ContainerPlugin):
    """containerd plugin.

    References:
        - https://containerd.io/docs/main/
        - https://github.com/containerd/containerd/blob/main/docs/content-flow.md
    """

    __namespace__ = "containerd"

    SYSTEM_PATHS = (
        # Default containerd system-wide install (Kubernetes, Docker, etc)
        "/var/lib/containerd",
        # Kubernetes rancher
        "/var/lib/rancher/k3s/agent/containerd",
        "/var/lib/rancher/rke2/agent/containerd",
        # Kubernetes microK8s
        "/var/snap/microk8s/current/var/lib/containerd",
        # Kubernetes k0s
        "/var/lib/k0s/containerd",
        # Docker built-in containerd
        "/var/lib/docker/containerd",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.installs: set[tuple[Path, Bbolt, str]] = set(self.find_installs())
        # TODO: Parse /etc/containerd/config.toml for custom 'root' directives.

    def find_installs(self) -> Iterator[tuple[Path, Bbolt, str]]:
        """Yield containerd installs.

        Formatted as a tuple with:
            - :class:`Path` of root containerd install
            - :class:`Bbolt` database instance of ``meta.db``
            - the bbolt namespace string (e.g. ``moby`` or ``k8s.io``)
        """
        for path in self.SYSTEM_PATHS:
            if not (dir := self.target.fs.path(path)).is_dir():
                continue

            if not (meta_path := dir.joinpath("io.containerd.metadata.v1.bolt/meta.db")).is_file():
                self.target.log.warning("Containerd install %s does not contain meta.db", dir)
                continue

            try:
                meta_db = Bbolt(meta_path)
            except Exception as e:
                self.target.log.warning("Unable to parse containerd meta.db file %s: %s", meta_path, e)
                continue

            try:
                ns = infer_bbolt_namespace(meta_db)
            except ValueError as e:
                self.target.log.warning("Unable to determine containerd meta.db namespace %s: %s", meta_path, e)
                continue

            yield dir, meta_db, ns

    def check_compatible(self) -> None:
        if not self.installs:
            raise UnsupportedPluginError("No containerd installs found on target")

    @export(record=ContainerdImageRecord)
    def images(self) -> Iterator[ContainerdImageRecord]:
        """Yield any pulled containerd images on the target."""
        for _install, meta_db, ns in self.installs:
            if not (images := meta_db.keys(f"v1 {ns} images")):
                continue

            for image_name in images:
                if "@" in image_name:
                    name, _, tag = image_name.rpartition("@")
                elif ":" in image_name and not image_name.startswith("sha256:"):
                    name, _, tag = image_name.rpartition(":")
                else:
                    name = image_name
                    tag = None

                digest: str = meta_db.get(f"v1 {ns} images {image_name} target digest")  # type: ignore
                created_at: bytes = meta_db.get(f"v1 {ns} images {image_name} createdat", decode=False)  # type: ignore

                yield ContainerdImageRecord(
                    name=name,
                    tag=tag,
                    image_id=hash_to_image_id(digest) if digest else None,
                    created=golangtimestamp(created_at) if created_at else None,
                    hash=digest,
                    source=meta_db.path,
                    _target=self.target,
                )

    @export(record=ContainerdContainerRecord)
    def containers(self) -> Iterator[ContainerdContainerRecord]:
        """Yield any containerd containers on the target system.

        Not all implementors of containerd use this. For example Docker uses ``/var/lib/docker/containers`` instead.
        """
        for _install, meta_db, ns in self.installs:
            if not (containers := meta_db.keys(f"v1 {ns} containers")):
                continue

            for container_id in containers:
                spec_path = None
                spec = {}
                meta_path = None
                meta = {}

                if raw_spec := meta_db.get(f"v1 {ns} containers {container_id} spec", decode=False):
                    try:
                        spec_path, spec = unmarshal_any_json(raw_spec)
                    except ValueError as e:
                        self.target.log.warning(
                            "Failed to decode typeurl structure %s for container %s: %s", spec_path, container_id, e
                        )

                if raw_meta := meta_db.get(
                    f"v1 {ns} containers {container_id} extensions io.cri-containerd.sandbox.metadata", decode=False
                ):
                    try:
                        meta_path, meta = unmarshal_any_json(raw_meta)
                    except ValueError as e:
                        self.target.log.warning(
                            "Failed to decode typeurl structure %s for container %s: %s", meta_path, container_id, e
                        )

                volumes = [
                    f"{mount_point.get('source')}:{mount_point.get('destination')}"
                    for mount_point in spec.get("mounts", [])
                    if mount_point.get("type") == "bind"
                ]

                created_at: bytes = meta_db.get(f"v1 {ns} containers {container_id} createdat", decode=False)  # type: ignore

                # NOTE: The following fields cannot be populated with the information we have here:
                # image_id, command, running, pid, started, finished, config_path, image_path
                yield ContainerdContainerRecord(
                    container_id=container_id,
                    image=meta_db.get(f"v1 {ns} containers {container_id} image"),
                    created=golangtimestamp(created_at) if created_at else None,
                    ports=[
                        f"0.0.0.0:{port.get('container_port')}->{port.get('container_port')}/tcp"
                        for port in meta.get("Metadata", {}).get("Config", {}).get("port_mappings", [])
                    ],
                    name=meta.get("Metadata", {}).get("Name"),  # or ``labels io.kubernetes.container.name``
                    volumes=volumes,
                    environment=spec.get("process", {}).get("env", []),
                    mount_path=meta_db.path.joinpath(container_id),
                    source=meta_db.path,
                    _target=self.target,
                )

    @export(record=ContainerdLogRecord)
    def logs(self) -> Iterator[ContainerdLogRecord]:
        """Yield any containerd log entries (stdout/stderr) from containers.

        Not all implementors of containerd use this. For example Docker uses ``/var/lib/docker/containers/*/*.log``.
        """
        if not (dir := self.target.fs.path("/var/log/containers")).is_dir():
            return

        for log_path in dir.iterdir():
            with log_path.open("rt", errors="backslashreplace") as fh:
                for entry in parse_ctr_log(fh):
                    yield ContainerdLogRecord(
                        container=log_path.stem,
                        **entry,
                        source=log_path,
                        _target=self.target,
                    )


def infer_bbolt_namespace(db: Bbolt) -> str:
    """Infer the :class:`Bbolt` containerd v1 namespace.

    Raises:
        ValueError if bbolt namespace could not be determined

    Returns: inferred namespace name.
    """
    if not (root_keys := db.keys("v1")):
        raise ValueError("Unsupported bbolt database version")

    if "moby" in root_keys:
        return "moby"

    if "k8s.io" in root_keys:
        return "k8s.io"

    raise ValueError(f"Unable to determine namespace ({root_keys})")


def parse_ctr_log(fh: TextIO) -> Iterator[dict]:
    """Yield CTR log entries (e.g. containerd or podman) from the provided file handle."""
    buf = ""
    for line in fh:
        if not (match := RE_CTR_LOG.match(line)):
            log.warning("Unable to match ctr log line %r in file handle %s", line, fh)
            continue

        entry = match.groupdict()
        type = entry.pop("type")

        # Each character has it's own log line and can be concatenated up until we encounter an empty 'F'.
        if type == "P":
            buf += entry["message"]
            continue

        if type == "F" and entry["message"] == "":
            entry["message"] = buf
            buf = ""

        yield entry
