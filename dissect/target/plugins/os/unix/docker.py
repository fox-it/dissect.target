from dissect.target.plugin import Plugin, export, internal
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target import Target

import json
import re

DockerContainerRecord = TargetRecordDescriptor(
    "linux/docker/container",
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
        ("string", "source"),
    ],
)


class DockerPlugin(Plugin):
    """
    Resources:
    - https://didactic-security.com/resources/docker-forensics.pdf
    - https://didactic-security.com/resources/docker-forensics-cheatsheet.pdf
    - https://github.com/google/docker-explorer
    """

    __namespace__ = "docker"

    DOCKER_PATH = "/var/lib/docker"
    # TODO: add more locations such as /home/local/docker

    def __init__(self, target: Target):
        super().__init__(target)

    def check_compatible(self):
        return self.target.fs.path(self.DOCKER_PATH).exists()

    @export(record=DockerContainerRecord)
    def containers(self):

        containers_path = f"{self.DOCKER_PATH}/containers"
        for container in self.target.fs.path(containers_path).iterdir():
            fp = self.target.fs.path(f"{container}/config.v2.json")

            if fp.exists():
                with fp.open() as cf:
                    config = json.load(cf)

                    if config.get("State").get("FinishedAt") == "0001-01-01T00:00:00Z":
                        finished = False
                    else:
                        finished = config.get("State").get("FinishedAt")

                    if config.get("State").get("Running"):
                        ports = config.get("NetworkSettings").get("Ports")
                        pid = config.get("Pid")
                    else:
                        ports = config.get("Config").get("ExposedPorts")
                        pid = False

                    # TODO: Yield any present MountPoints / volumes

                    yield DockerContainerRecord(
                        container_id=config.get("ID"),
                        image=config.get("Config").get("Image"),
                        command=config.get("Config").get("Cmd"),
                        created=_convert_timestamp(config.get("Created")),
                        running=config.get("State").get("Running"),
                        pid=pid,
                        started=_convert_timestamp(config.get("State").get("StartedAt")),
                        finished=finished,
                        ports=_convert_ports(ports),
                        names=config.get("Name").replace("/", "", 1),
                        source=fp,
                        _target=self.target,
                    )


def _convert_timestamp(timestamp):
    """
    Docker sometimes uses (unpadded) 9 digit nanosecond precision
    in their timestamp logs, eg. "2022-12-19T13:37:00.123456789Z".
    Python has no native %n nanosecond strptime directive, so we
    strip the last three digits from the timestamp to force
    compatbility with the 6 digit %f microsecond directive.
    """
    if re.search(r"\.([0-9]{9})Z$", timestamp[19:]):
        return re.sub(r"([0-9]{3})Z$", r"Z", timestamp)
    else:
        return timestamp


def _convert_ports(ports):
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
    for p in ports:

        if type(ports[p]) == list:
            # NOTE: We ignore IPv6 assignments here.
            fports[p] = f"{ports[p][0]['HostIp']}:{ports[p][0]['HostPort']}"
        elif type(ports[p]) == dict:
            # NOTE: We make the assumption the default broadcast ip 0.0.0.0 was used.
            fports[p] = f"0.0.0.0:{p.split('/')[0]}"

    return fports
