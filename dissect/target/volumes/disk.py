from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.volume import disk

from dissect.target.volume import Volume, VolumeSystem

if TYPE_CHECKING:
    from collections.abc import Iterator


class DissectVolumeSystem(VolumeSystem):
    __type__ = "disk"

    def __init__(self, fh: BinaryIO | list[BinaryIO], *args, **kwargs):
        self._disk = disk.Disk(fh)
        super().__init__(fh, *args, serial=self._disk.serial, **kwargs)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        try:
            disk.Disk(fh)
        except Exception:
            return False
        else:
            return True

    def _volumes(self) -> Iterator[Volume]:
        for v in self._disk.partitions:
            name = v.name or f"part_{v.offset:08x}"
            yield Volume(
                v.open(),
                v.number,
                v.offset,
                v.size,
                v.type,
                name,
                guid=v.guid,
                raw=v,
                disk=self.disk,
                vs=self,
            )
