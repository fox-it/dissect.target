from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, BinaryIO

from dissect.vmfs import lvm
from dissect.vmfs.c_lvm import c_lvm

from dissect.target.helpers.utils import to_list
from dissect.target.volume import LogicalVolumeSystem, Volume

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self


class VmfsVolumeSystem(LogicalVolumeSystem):
    __type__ = "vmfs"

    def __init__(
        self,
        fh: BinaryIO | list[BinaryIO],
        *args,
        devices: list[lvm.Device] | None = None,
        **kwargs,
    ):
        self.lvm = lvm.LVM(devices if devices is not None else fh)
        super().__init__(fh, *args, **kwargs)

    @classmethod
    def open_all(cls, volumes: list[BinaryIO]) -> Iterator[Self]:
        lvm_volumes = defaultdict(list)
        source_disks: dict[tuple[bytes, bytes], dict[BinaryIO, None]] = {}

        for vol in volumes:
            if not cls.detect_volume(vol):
                continue

            device = lvm.Device(vol)
            for lv_meta in device.volumes:
                lv_id = (bytes(lv_meta.volMeta.lvID.uuid), lv_meta.volMeta.lvID.snapID)
                lvm_volumes[lv_id].append(device)

                disks = source_disks.setdefault(lv_id, {})
                for disk in to_list(vol.disk if isinstance(vol, Volume) else vol):
                    disks[disk] = None

        for lv_id, devices in lvm_volumes.items():
            try:
                source_fhs = [dev.fh for dev in devices]
                yield cls(
                    source_fhs[0] if len(source_fhs) == 1 else source_fhs,
                    devices=devices,
                    disk=list(source_disks[lv_id]),
                )
            except Exception:  # noqa: PERF203
                continue

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        return VmfsVolumeSystem.detect_volume(fh)

    @staticmethod
    def _detect_volume(fh: BinaryIO) -> bool:
        fh.seek(c_lvm.LVM_DEV_HEADER_OFFSET)
        sector = fh.read(512)
        return int.from_bytes(sector[:4], "little") == c_lvm.LVM_MAGIC_NUMBER

    def _volumes(self) -> Iterator[Volume]:
        for i, volume in enumerate(self.lvm.volumes):
            yield Volume(
                fh=volume.open(),
                number=i + 1,
                offset=None,
                size=volume.size,
                vtype=None,
                name=volume.name,
                guid=volume.uuid,
                raw=volume,
                disk=self.disk,
                vs=self,
            )
