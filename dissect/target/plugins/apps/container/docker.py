from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Iterator, Optional

from dissect.cstruct import cstruct
from dissect.util import ts

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.protobuf import ProtobufVarint
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

# Resources:
# - https://github.com/moby/moby/pull/37092
# - https://github.com/cpuguy83/docker/blob/master/daemon/logger/local/doc.go
# - https://github.com/moby/moby/blob/master/api/types/plugins/logdriver/entry.proto
local_def = """
struct entry {
    uint32   header;

    // source
    uint8    s_type;        // 0x0a
    varint   s_len;         // 0x06
    char     source[s_len]; // stdout or stderr

    // timestamp
    uint8    t_type;        // 0x10
    varint   ts;            // timestamp in ums

    // message
    uint8    m_type;        // 0x1a
    varint   m_len;         // message length
    char     message[m_len];

    // partial_log_metadata not implemented

    uint32 footer;
};
"""

c_local = cstruct(endian=">")
c_local.addtype("varint", ProtobufVarint(c_local, "varint", size=None, signed=False, alignment=1))
c_local.load(local_def, compiled=False)

RE_DOCKER_NS = re.compile(r"\.(?P<nanoseconds>\d{7,})(?P<postfix>Z|\+\d{2}:\d{2})")
RE_ANSI_ESCAPE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

ASCII_MAP = {
    "\x08": "[BS]",
    "\x09": "[TAB]",
    "\x0A": "",  # \n
    "\x0D": "",  # \r
}


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
                continue

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


def convert_timestamp(timestamp: str) -> str:
    """Docker sometimes uses (unpadded) 9 digit nanosecond precision
    in their timestamp logs, eg. "2022-12-19T13:37:00.123456789Z".

    Python has no native %n nanosecond strptime directive, so we
    strip the last three digits from the timestamp to force
    compatbility with the 6 digit %f microsecond directive.
    """

    timestamp_nanoseconds_plus_postfix = timestamp[19:]
    match = RE_DOCKER_NS.match(timestamp_nanoseconds_plus_postfix)

    # Timestamp does not have nanoseconds if there is no match.
    if not match:
        return timestamp

    # Take the first six digits and reconstruct the timestamp.
    match = match.groupdict()
    microseconds = match["nanoseconds"][:6]
    return f"{timestamp[:19]}.{microseconds}{match['postfix']}"


def convert_ports(ports: dict[str, list | dict]) -> dict:
    """Depending on the state of the container (turned on or off) we
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


def hash_to_image_id(hash: str) -> str:
    """Convert the hash to an abbrevated docker image id."""
    return hash.split(":")[-1][:12]


def strip_log(input: str | bytes, exc_backspace: bool = False) -> str:
    """Remove ANSI escape sequences from a given input string.

    Also translates ASCII codes such as backspaces to readable format.

    Resources:
        - https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797#general-ascii-codes
    """

    if isinstance(input, bytes):
        input = input.decode("utf-8", errors="backslashreplace")

    out = RE_ANSI_ESCAPE.sub("", input)

    if exc_backspace:
        out = _replace_backspace(out)

    for hex, name in ASCII_MAP.items():
        out = out.replace(hex, name)

    return out


def _replace_backspace(input: str) -> str:
    """Remove ANSI backspace characters (``\x08``) and 'replay' their effect on the rest of the string.

    For example, with the input ``123\x084``, the output would be ``124``.
    """
    out = ""
    for char in input:
        if char == "\x08":
            out = out[:-1]
        else:
            out += char
    return out
