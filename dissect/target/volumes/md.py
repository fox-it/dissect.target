from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.volume.md.md import MD, MDPhysicalDisk, find_super_block

from dissect.target.volume import LogicalVolumeSystem, Volume

if TYPE_CHECKING:
    from collections.abc import Iterator
    from uuid import UUID

    from typing_extensions import Self


class MdVolumeSystem(LogicalVolumeSystem):
    __type__ = "md"

    def __init__(self, fh: BinaryIO | list[BinaryIO] | None, *args, **kwargs):
        self.md = MD(fh)
        super().__init__(fh, *args, **kwargs)

    @classmethod
    def open_all(cls, volumes: list[BinaryIO]) -> Iterator[Self]:
        devices: dict[UUID, list[MDPhysicalDisk]] = {}

        for vol in volumes:
            if not cls.detect_volume(vol):
                continue

            device = MDPhysicalDisk(vol)
            devices.setdefault(device.set_uuid, []).append(device)

        for devs in devices.values():
            try:
                yield cls(devs, disk=[dev.fh for dev in devs])
            except Exception:  # noqa: PERF203
                continue

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        vols = [fh] if not isinstance(fh, list) else fh
        return any(MdVolumeSystem.detect_volume(vol) for vol in vols)

    @staticmethod
    def _detect_volume(fh: BinaryIO) -> bool:
        offset, _, _ = find_super_block(fh)
        return offset is not None

    def _volumes(self) -> Iterator[Volume]:
        # MD only supports one configuration and virtual disk but doing this as a loop
        # makes it automatically safe for empty configurations
        for conf in self.md.configurations:
            for vd in conf.virtual_disks:
                fh = vd.open()
                yield Volume(fh, 1, None, vd.size, None, vd.name, vd.uuid, raw=self.md, disk=self.disk, vs=self)
