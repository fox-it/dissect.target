import logging
from collections import defaultdict
from typing import BinaryIO, Iterator, Union

from dissect.vmfs import lvm
from dissect.vmfs.c_vmfs import c_vmfs

from dissect.target.volume import LogicalVolumeSystem, Volume

log = logging.getLogger(__name__)


class VmfsVolumeSystem(LogicalVolumeSystem):
    __type__ = "vmfs"

    def __init__(self, fh: Union[BinaryIO, list[BinaryIO]], *args, **kwargs):
        self.lvm = lvm.LVM(fh)
        super().__init__(fh, *args, **kwargs)

    @classmethod
    def open_all(cls, volumes: list[BinaryIO]) -> Iterator[LogicalVolumeSystem]:
        lvm_extents = defaultdict(list)

        for vol in volumes:
            if not cls.detect_volume(vol):
                continue

            extent = lvm.Extent(vol)
            lvm_extents[extent.uuid].append(extent)

        for pvs in lvm_extents.values():
            try:
                yield cls(pvs)
            except Exception:
                continue

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        return VmfsVolumeSystem.detect_volume(fh)

    @staticmethod
    def _detect_volume(fh: BinaryIO) -> bool:
        fh.seek(c_vmfs.VMFS_LVM_DEVICE_META_BASE)
        sector = fh.read(512)
        return int.from_bytes(sector[:4], "little") == c_vmfs.VMFS_LVM_DEVICE_META_MAGIC

    def _volumes(self) -> Iterator[Volume]:
        try:
            name = next(extent.fh.name for extent in self.fh if hasattr(extent.fh, "name"))
        except StopIteration:
            name = None

        yield Volume(
            self.lvm,
            1,
            None,
            self.lvm.size,
            None,
            name,
            self.lvm.uuid,
            raw=self.lvm,
            vs=self,
        )
