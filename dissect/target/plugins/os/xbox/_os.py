from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.record import EmptyRecord
from dissect.target.plugin import OperatingSystem, OSPlugin, export, internal

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class XboxPlugin(OSPlugin):
    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for disk in target.disks:
            if disk.vs.__type__ == "xbox":
                for volume in disk.vs.volumes:
                    if volume.name == "C":
                        return volume.fs

        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        target.fs.case_sensitive = False
        target.fs.alt_separator = "\\"

        for disk in target.disks:
            if disk.vs.__type__ == "xbox":
                for volume in disk.vs.volumes:
                    if volume.fs:
                        target.fs.mount(volume.name.lower() + ":", volume.fs)

        return cls(target)

    @export(property=True)
    def hostname(self) -> str | None:
        return "XBOX"

    @export(property=True)
    def ips(self) -> list[str]:
        return []

    @export(property=True)
    def version(self) -> str | None:
        return None

    @export(property=True)
    def architecture(self) -> str | None:
        return None

    @export(record=EmptyRecord)
    def users(self) -> Iterator[EmptyRecord]:
        yield from ()

    @internal
    def misc_user_paths(self) -> Iterator[tuple[str, tuple[str, str] | None]]:
        yield from ()

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.XBOX
