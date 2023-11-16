from collections import defaultdict
from typing import BinaryIO, Iterator, Union

from dissect.volume.md.md import MD, Device, find_super_block

from dissect.target.volume import LogicalVolumeSystem, Volume


class MdVolumeSystem(LogicalVolumeSystem):
    __type__ = "md"

    def __init__(self, fh: Union[BinaryIO, list[BinaryIO]], *args, **kwargs):
        self.md = MD(fh)
        super().__init__(fh, *args, **kwargs)

    @classmethod
    def open_all(cls, volumes: list[BinaryIO]) -> Iterator[LogicalVolumeSystem]:
        devices = defaultdict(list)

        for vol in volumes:
            if not cls.detect_volume(vol):
                continue

            device = Device(vol)
            devices[device.set_uuid].append(device)

        for devs in devices.values():
            try:
                yield cls(devs)
            except Exception:
                continue

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        vols = [fh] if not isinstance(fh, list) else fh
        for vol in vols:
            if MdVolumeSystem.detect_volume(vol):
                return True
        return False

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
                yield Volume(fh, 1, None, vd.size, None, vd.name, vd.uuid, raw=self.md, vs=self)
