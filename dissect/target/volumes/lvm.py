import logging
from collections import defaultdict
from typing import BinaryIO, Iterator, Union

from dissect.volume import lvm

from dissect.target.volume import LogicalVolumeSystem, Volume

log = logging.getLogger(__name__)

OPEN_TYPES = (
    "linear",
    "striped",
    "mirror",
    "thin",
)

KNOWN_SKIP_TYPES = (
    "snapshot",
    "thin-pool",
)


class LvmVolumeSystem(LogicalVolumeSystem):
    __type__ = "lvm"

    def __init__(self, fh: Union[BinaryIO, list[BinaryIO]], *args, **kwargs):
        self.lvm = lvm.LVM2(fh)
        super().__init__(fh, *args, **kwargs)

    @classmethod
    def open_all(cls, volumes: list[BinaryIO]) -> Iterator[LogicalVolumeSystem]:
        lvm_pvs = defaultdict(list)

        for vol in volumes:
            if not cls.detect_volume(vol):
                continue

            dev = lvm.LVM2Device(vol)
            if metadata := dev.metadata:
                vg_name = next(key for key, value in metadata.items() if isinstance(value, dict))
                lvm_pvs[vg_name].append(dev)

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
        num = 1

        for lv_name, lv in self.lvm.volume_group.logical_volumes.items():
            if lv.type not in OPEN_TYPES:
                if lv.type not in KNOWN_SKIP_TYPES:
                    log.debug("Skipping unsupported LVM logical volume type: %s (%s)", lv.type, lv)
                continue

            # When composing a vg-lv name, LVM2 replaces hyphens with double hyphens in the vg and lv names
            # Emulate that here for the volume name
            name = f"{lv.vg.name.replace('-', '--')}-{lv_name.replace('-', '--')}"

            fh = lv.open()
            yield Volume(fh, num, None, fh.size, None, name, raw=lv, vs=self)

            num += 1
