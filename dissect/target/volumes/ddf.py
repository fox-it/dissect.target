import io
from collections import defaultdict
from typing import BinaryIO, Iterator, Union

from dissect.volume.ddf.ddf import DDF, DEFAULT_SECTOR_SIZE, DDFPhysicalDisk

from dissect.target.volume import LogicalVolumeSystem, Volume


class DdfVolumeSystem(LogicalVolumeSystem):
    __type__ = "ddf"

    def __init__(self, fh: Union[BinaryIO, list[BinaryIO]], *args, **kwargs):
        self.ddf = DDF(fh)
        super().__init__(fh, *args, **kwargs)

    @classmethod
    def open_all(cls, volumes: list[BinaryIO]) -> Iterator[LogicalVolumeSystem]:
        sets = defaultdict(list)

        for vol in volumes:
            if not cls.detect_volume(vol):
                continue

            disk = DDFPhysicalDisk(vol)
            sets[disk.anchor.DDF_Header_GUID].append(disk)

        for devs in sets.values():
            try:
                yield cls(devs)
            except Exception:
                continue

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        vols = [fh] if not isinstance(fh, list) else fh
        for vol in vols:
            if DdfVolumeSystem.detect_volume(vol):
                return True
        return False

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
                yield Volume(fh, 1, None, vd.size, None, vd.name, vd.uuid, raw=self.ddf, vs=self)
