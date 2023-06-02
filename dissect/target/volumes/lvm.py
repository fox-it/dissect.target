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
    def _detect(fh: BinaryIO) -> bool:
        vols = [fh] if not isinstance(fh, list) else fh
        for vol in vols:
            if LvmVolumeSystem.detect_volume(vol):
                return True
        return False

    @staticmethod
    def _detect_volume(fh: BinaryIO) -> bool:
        buf = fh.read(4096)
        return b"LABELONE" in buf

    def _volumes(self) -> Iterator[Volume]:
        for num, lv in enumerate(self.lvm.volume_group.logical_volumes):
            # When composing a vg-lv name, LVM2 replaces hyphens with double hyphens in the vg and lv names
            # Emulate that here for the volume name
            name = f"{lv.vg.name.replace('-', '--')}-{lv.metadata.name.replace('-', '--')}"
            yield Volume(lv, num, None, lv.size, None, name, raw=lv, vs=self)
