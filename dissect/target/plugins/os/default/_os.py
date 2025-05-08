from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.record import EmptyRecord
from dissect.target.plugin import OSPlugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record import Record
    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class DefaultOSPlugin(OSPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        if len(target.filesystems) == 1:
            target.fs.mount("/", target.filesystems[0])
        else:
            for i, fs in enumerate(target.filesystems):
                target.fs.mount(f"fs{i}", fs)

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        pass

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        if sysvol:
            target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> str | None:
        pass

    @export(property=True)
    def ips(self) -> list[str]:
        return []

    @export(property=True)
    def version(self) -> str | None:
        pass

    @export(record=EmptyRecord)
    def users(self) -> Iterator[Record]:
        yield from ()

    @export(property=True)
    def os(self) -> str:
        return "default"

    @export(property=True)
    def architecture(self) -> str | None:
        pass
