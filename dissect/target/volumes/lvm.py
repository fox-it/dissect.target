from __future__ import annotations

import logging
from typing import TYPE_CHECKING, BinaryIO

from dissect.volume import lvm

from dissect.target.volume import LogicalVolumeSystem, Volume

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

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

    def __init__(self, fh: BinaryIO | list[BinaryIO], *args, **kwargs):
        self.lvm = lvm.LVM2(fh)
        super().__init__(fh, *args, **kwargs)

    @classmethod
    def open_all(cls, volumes: list[BinaryIO]) -> Iterator[Self]:
        devices: dict[str, list[lvm.LVM2Device]] = {}

        for vol in volumes:
            if not cls.detect_volume(vol):
                continue

            dev = lvm.LVM2Device(vol)
            if metadata := dev.metadata:
                vg_name = next(key for key, value in metadata.items() if isinstance(value, dict))
                devices.setdefault(vg_name, []).append(dev)

        for pvs in devices.values():
            try:
                yield cls(pvs, disk=[pv.fh for pv in pvs])
            except Exception:  # noqa: PERF203
                continue

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        vols = [fh] if not isinstance(fh, list) else fh
        return any(LvmVolumeSystem.detect_volume(vol) for vol in vols)

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
            yield Volume(fh, num, None, fh.size, None, name, raw=lv, disk=self.disk, vs=self)

            num += 1
