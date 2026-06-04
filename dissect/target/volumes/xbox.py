from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import RangeStream

from dissect.target.volume import Volume, VolumeSystem

if TYPE_CHECKING:
    from collections.abc import Iterator


class XboxVolumeSystem(VolumeSystem):
    __type__ = "xbox"

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        fh.seek(0x00000600)
        return fh.read(4) in (b"RFRB", b"BRFR")

    def _volumes(self) -> Iterator[Volume]:
        for number, name, offset, size in [
            # Retail partitions
            (3, "X", 0x00080000, 0x02EE00000),
            (4, "Y", 0x2EE80000, 0x02EE00000),
            (5, "Z", 0x5DC80000, 0x02EE00000),
            (2, "C", 0x8CA80000, 0x01F400000),
            (1, "E", 0xABE80000, 0x131F00000),
            # Extended (non-retail) partitions commonly used in homebrew
            (6, "F", 0x1DD156000, None),
        ]:
            yield Volume(
                RangeStream(self.fh, offset, size),
                number,
                offset,
                size,
                "fatx",
                name,
                disk=self.disk,
                vs=self,
            )
