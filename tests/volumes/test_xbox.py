from __future__ import annotations

from dissect.target import container, volume
from dissect.target.volumes.xbox import XboxVolumeSystem
from tests._utils import absolute_path


def test_xbox_volume() -> None:
    """Test if we can detect and map all partitions from an Xbox HDD."""
    with absolute_path("_data/volumes/xbox/xbox_hdd.qcow2").open("rb") as fh:
        disk = container.open(fh)

        assert XboxVolumeSystem.detect(disk)

        vs = volume.open(disk)
        assert isinstance(vs, XboxVolumeSystem)

        assert len(vs.volumes) == 6
        assert [(v.number, v.offset, v.size, v.type, v.name) for v in vs.volumes] == [
            (3, 0x00080000, 0x02EE00000, "fatx", "X"),
            (4, 0x2EE80000, 0x02EE00000, "fatx", "Y"),
            (5, 0x5DC80000, 0x02EE00000, "fatx", "Z"),
            (2, 0x8CA80000, 0x01F400000, "fatx", "C"),
            (1, 0xABE80000, 0x131F00000, "fatx", "E"),
            (6, 0x1DD156000, None, "fatx", "F"),
        ]

        for vol in vs.volumes:
            assert vol.disk is disk
            assert vol.vs is vs

            if vol.name != "F":
                vol.seek(0)
                assert vol.read(4) == b"FATX"
