from __future__ import annotations

from typing import Iterator, Optional

from dissect.target.filesystem import Filesystem
from dissect.target.helpers import configutil
from dissect.target.helpers.record import EmptyRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.target import Target


class AndroidPlugin(LinuxPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self.target = target

        self.props = {}
        if (build_prop := self.target.fs.path("/build.prop")).exists():
            self.props = configutil.parse(build_prop, separator=("=",), comment_prefixes=("#",)).parsed_data

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
    def hostname(self) -> Optional[str]:
        return self.props.get("ro.build.host")

    @export(property=True)
    def ips(self) -> list[str]:
        return []

    @export(property=True)
    def version(self) -> str:
        full_version = "Android"

        release_version = self.props.get("ro.build.version.release")
        if release_version := self.props.get("ro.build.version.release"):
            full_version += f" {release_version}"

        if security_patch_version := self.props.get("ro.build.version.security_patch"):
            full_version += f" ({security_patch_version})"

        return full_version

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.ANDROID.value

    @export(record=EmptyRecord)
    def users(self) -> Iterator[EmptyRecord]:
        yield from ()
