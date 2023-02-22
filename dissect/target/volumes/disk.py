from typing import BinaryIO, Iterator, Union

from dissect.volume import disk

from dissect.target.volume import Volume, VolumeSystem


class DissectVolumeSystem(VolumeSystem):
    def __init__(self, fh: Union[BinaryIO, list[BinaryIO]], *args, **kwargs):
        self._disk = disk.Disk(fh)
        super().__init__(fh, serial=self._disk.serial, *args, **kwargs)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        try:
            disk.Disk(fh)
            return True
        except Exception:
            return False

    def _volumes(self) -> Iterator[Volume]:
        for v in self._disk.partitions:
            name = v.name or f"part_{v.offset:08x}"
            yield Volume(
                v.open(),
                v.number,
                v.offset,
                v.size,
                v.type,
                name,
                guid=v.guid,
                raw=v,
                disk=self.disk,
                vs=self,
            )
