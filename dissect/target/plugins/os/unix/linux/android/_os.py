from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers import configutil
from dissect.target.helpers.record import EmptyRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class AndroidPlugin(LinuxPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self.target = target

        self.build_prop_paths = set(find_build_props(self.target.fs))
        self.props = {}

        for build_prop in self.build_prop_paths:
            try:
                self.props.update(configutil.parse(build_prop, separator=("=",), comment_prefixes=("#",)).parsed_data)
            except Exception as e:  # noqa: PERF203
                self.target.log.warning("Unable to parse Android build.prop file %s: %s", build_prop, e)

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        ANDROID_PATHS = (
            "data",
            "system",
            "vendor",
            "product",
        )

        for fs in target.filesystems:
            if all(fs.exists(p) for p in ANDROID_PATHS) and any(find_build_props(fs)):
                return fs
        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> str | None:
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


def find_build_props(fs: Filesystem) -> Iterator[Path]:
    """Search for Android ``build.prop`` files on the provided :class:`Filesystem`."""
    if (root_prop := fs.path("/build.prop")).is_file():
        yield root_prop

    for prop in fs.path("/").glob("*/build.prop"):
        if prop.is_file():
            yield prop
