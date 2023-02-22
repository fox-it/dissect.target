from __future__ import annotations

from typing import Iterator, Optional, TextIO

from dissect.target.filesystem import Filesystem
from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugin import OperatingSystem, OSPlugin, export
from dissect.target.target import Target


class BuildProp:
    def __init__(self, fh: TextIO):
        self.props = {}

        for line in fh:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            k, v = line.split("=")
            self.props[k] = v


class AndroidPlugin(OSPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self.target = target
        self.props = BuildProp(self.target.path("/build.prop").open("rt"))

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        for fs in target.filesystems:
            if fs.exists("/build.prop"):
                return fs
        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> AndroidPlugin:
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> str:
        return self.props.props["ro.build.host"]

    @export(property=True)
    def ips(self) -> list[str]:
        return []

    @export(property=True)
    def version(self) -> str:
        release_version = self.props.props["ro.build.version.release"]
        security_patch_version = self.props.props["ro.build.version.security_patch"]
        return f"Android {release_version} ({security_patch_version})"

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.ANDROID.value

    def users(self) -> Iterator[UnixUserRecord]:
        raise NotImplementedError()
