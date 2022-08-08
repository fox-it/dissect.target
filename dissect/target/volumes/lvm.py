from collections import defaultdict
from typing import BinaryIO, Iterator, Union

from dissect.volume import lvm

from dissect.target.volume import LogicalVolumeSystem, Volume


class LvmVolumeSystem(LogicalVolumeSystem):
    def __init__(self, fh: Union[BinaryIO, list[BinaryIO]], *args, **kwargs):
        self.lvm = lvm.LVM2(fh)
        super().__init__(fh, *args, **kwargs)

    @classmethod
    def open_all(cls, volumes: list[BinaryIO]) -> Iterator[LogicalVolumeSystem]:
        lvm_pvs = defaultdict(list)

        for vol in volumes:
            if not cls.detect_volume(vol):
                continue

            pv = lvm.PhysicalVolume(vol)
            if pv.has_metadata():
                try:
                    m = pv.read_metadata()
                except Exception:
                    continue
                lvm_pvs[m.vg.name].append(pv)

        for pvs in lvm_pvs.values():
            try:
                yield cls(pvs)
            except Exception:
                continue

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        vols = [fh] if not isinstance(fh, list) else fh
        for vol in vols:
            if LvmVolumeSystem.detect_volume(vol):
                return True
        return False

    @staticmethod
    def detect_volume(fh: BinaryIO) -> bool:
        try:
            offset = fh.tell()
            buf = fh.read(4096)
            fh.seek(offset)
            return b"LABELONE" in buf
        except Exception:  # noqa
            return False

    def _volumes(self) -> Iterator[Volume]:
        for num, lv in enumerate(self.lvm.volume_group.logical_volumes):
            name = f"{lv.vg.name}-{lv.metadata.name}"
            yield Volume(lv, num, None, lv.size, None, name, raw=lv, vs=self)
