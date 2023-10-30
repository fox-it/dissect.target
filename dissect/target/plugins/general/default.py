from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from flow.record import Record

    from dissect.target.target import Target
    from dissect.target.filesystem import Filesystem

from dissect.target.helpers.record import EmptyRecord
from dissect.target.plugin import OSPlugin, export


class DefaultPlugin(OSPlugin):
    __skip__ = True

    def __init__(self, target: Target):
        super().__init__(target)
        if len(target.filesystems) == 1:
            target.fs.mount("/", target.filesystems[0])
        else:
            for i, fs in enumerate(target.filesystems):
                target.fs.mount(f"fs{i}", fs)

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        pass

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> DefaultPlugin:
        if sysvol:
            target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> Optional[str]:
        pass

    @export(property=True)
    def ips(self) -> list[str]:
        return []

    @export(property=True)
    def version(self) -> Optional[str]:
        pass

    @export(record=EmptyRecord)
    def users(self) -> list[Record]:
        yield from ()

    @export(property=True)
    def os(self) -> str:
        return "default"

    @export(property=True)
    def architecture(self) -> Optional[str]:
        pass
