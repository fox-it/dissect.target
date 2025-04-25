from __future__ import annotations

import io
from typing import TYPE_CHECKING, BinaryIO

from dissect.volume.ddf.ddf import DDF, DEFAULT_SECTOR_SIZE, DDFPhysicalDisk

from dissect.target.volume import LogicalVolumeSystem, Volume

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self


class DdfVolumeSystem(LogicalVolumeSystem):
    __type__ = "ddf"

    def __init__(self, fh: BinaryIO | list[BinaryIO], *args, **kwargs):
        self.ddf = DDF(fh)
        super().__init__(fh, *args, **kwargs)

    @classmethod
    def open_all(cls, volumes: list[BinaryIO]) -> Iterator[Self]:
        sets: dict[bytes, list[DDFPhysicalDisk]] = {}

        for vol in volumes:
            if not cls.detect_volume(vol):
                continue

            disk = DDFPhysicalDisk(vol)
            sets.setdefault(disk.anchor.DDF_Header_GUID, []).append(disk)

        for devs in sets.values():
            try:
                yield cls(devs)
            except Exception:  # noqa: PERF203
                continue

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        vols = [fh] if not isinstance(fh, list) else fh
        return any(DdfVolumeSystem.detect_volume(vol) for vol in vols)

    @staticmethod
    def _detect_volume(fh: BinaryIO) -> bool:
        fh.seek(-DEFAULT_SECTOR_SIZE, io.SEEK_END)
        return int.from_bytes(fh.read(4), "big") == 0xDE11DE11

    def _volumes(self) -> Iterator[Volume]:
        # MD only supports one configuration and virtual disk but doing this as a loop
        # makes it automatically safe for empty configurations
        for conf in self.ddf.configurations:
            for vd in conf.virtual_disks:
                fh = vd.open()
                yield Volume(fh, 1, None, vd.size, None, vd.name, vd.uuid, raw=self.ddf, disk=self.disk, vs=self)
