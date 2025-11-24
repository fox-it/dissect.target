from __future__ import annotations

import io
from typing import TYPE_CHECKING
from unittest.mock import Mock, call, patch

from dissect.volume.lvm.physical import LVM2Device

from dissect.target.containers.raw import RawContainer
from dissect.target.plugins.scrape.scrape import ScrapePlugin
from dissect.target.volume import EncryptedVolumeSystem, LogicalVolumeSystem

if TYPE_CHECKING:
    from dissect.target.target import Target


class MockFactory:
    """Helper to generate complex mock volume structures quickly."""

    @staticmethod
    def create_disk(name: str = "disk0", size: int = 100_000) -> Mock:
        disk = Mock(name=name)
        disk.size = size
        disk.vs = Mock()
        disk.vs.volumes = []
        return disk

    @staticmethod
    def create_volume(name: str, backing_disk: Mock, offset: int, size: int) -> Mock:
        vol = Mock(name=name)
        vol.disk = backing_disk  # In dissect, .disk usually points to the physical disk
        vol.offset = offset
        vol.size = size
        vol.vs = None  # Default to no file system

        # Add to backing disk's VS list (mimicking a partition table)
        if backing_disk and hasattr(backing_disk, "vs") and backing_disk.vs:
            backing_disk.vs.volumes.append(vol)

        return vol

    @staticmethod
    def make_encrypted(volume: Mock, decrypted_vol_name: str) -> Mock:
        """Turns a volume into a LUKS container and returns the decrypted volume."""
        decrypted = Mock(name=decrypted_vol_name)
        decrypted.size = volume.size - 64  # Header overhead
        decrypted.offset = volume.offset
        decrypted.vs = None
        decrypted.disk = volume.disk  # Points to physical disk

        decrypted.vs = Mock(spec=EncryptedVolumeSystem)
        decrypted.vs.fh = volume

        return decrypted

    @staticmethod
    def make_lvm(name: str, backing_volumes: list[Mock], size: int | None = None) -> Mock:
        """Creates a Logical Volume spanning the backing_volumes."""
        if size is None:
            size = sum(v.size for v in backing_volumes)

        lv = Mock(name=name)
        lv.size = size
        lv.offset = 0
        lv.disk = [v.disk for v in backing_volumes]  # List of physical disks
        lv.vs = Mock()

        # Setup LVM relationship
        # The LV volume object's vs.fh is a list of PVs (backing volumes)
        lv.vs = Mock(spec=LogicalVolumeSystem)
        lv.vs.fh = [Mock(fh=bv) for bv in backing_volumes]  # wrap in source_dev style

        return lv


def test_create_streams_two_ordinary_volumes(target_bare: Target) -> None:
    """Test scrape streams for a standard physical disk with two partitions and gaps."""
    target_bare.add_plugin(ScrapePlugin)  # type: ignore

    # Setup
    disk = MockFactory.create_disk(size=100)
    vol1 = MockFactory.create_volume("vol1", disk, offset=10, size=20)
    vol2 = MockFactory.create_volume("vol2", disk, offset=50, size=20)

    target_bare.disks.add(disk)

    with patch("dissect.util.stream.MappingStream.add") as mock_add:
        streams = list(target_bare.scrape.create_streams())  # type: ignore

        # Assertions
        assert len(streams) == 1
        assert streams[0][0] == disk  # The stream key is the disk

        expected_calls = [
            call(0, 10, disk, 0),  # Gap at start
            call(10, 20, vol1, 0),  # Volume 1
            call(30, 20, disk, 30),  # Gap between
            call(50, 20, vol2, 0),  # Volume 2
            call(70, 30, disk, 70),  # Gap at end
        ]
        mock_add.assert_has_calls(expected_calls)


def test_create_streams_luks_lvm_luks(target_bare: Target) -> None:
    """Test scrape screams for LUKS -> LVM -> LUKS nested volumes."""
    target_bare.add_plugin(ScrapePlugin)

    # 1. Physical Layer
    disk = MockFactory.create_disk("phys_disk", size=1000)
    encrypted_outer = MockFactory.create_volume("part1", disk, offset=0, size=1000)

    # 2. Outer LUKS Layer (Part1 is encrypted)
    decrypted_outer = MockFactory.make_encrypted(encrypted_outer, "decrypted_outer")

    # 3. LVM Layer (Decrypted Outer is the PV)
    lv = MockFactory.make_lvm("lv_inner", [decrypted_outer], size=400)

    # 4. Inner LUKS Layer (LV is encrypted)
    decrypted_inner = MockFactory.make_encrypted(lv, "decrypted_inner")

    target_bare.disks.add(disk)

    target_bare.volumes.entries = [encrypted_outer, decrypted_outer, lv, decrypted_inner]

    with patch("dissect.util.stream.MappingStream.add") as mock_add:
        streams = list(target_bare.scrape.create_streams(encrypted=True, lvm=True))

        assert len(streams) == 1
        assert call(0, decrypted_inner.size, decrypted_inner, 0) in mock_add.call_args_list


def test_create_streams_lvm_luks_lvm(target_bare: Target) -> None:
    """
    Test Case 3: Nested LVM -> LUKS -> LVM
    Physical Disk -> Part1 (PV) -> LV1 (LUKS) -> Decrypted LV1 (PV) -> LV2
    """
    target_bare.add_plugin(ScrapePlugin)

    # 1. Physical Layer
    disk = MockFactory.create_disk("phys_disk", size=1000)
    part1 = MockFactory.create_volume("part1", disk, offset=0, size=1000)

    # 2. Outer LVM (Part1 is PV)
    lv1 = MockFactory.make_lvm("lv1_outer", [part1], size=480)

    # 3. LUKS Layer (LV1 is encrypted)
    decrypted_lv1 = MockFactory.make_encrypted(lv1, "decrypted_lv1")

    # 4. Inner LVM (Decrypted LV1 is PV)
    lv2 = MockFactory.make_lvm("lv2_inner", [decrypted_lv1], size=400)

    target_bare.disks.add(disk)
    target_bare.volumes.entries = [part1, lv1, decrypted_lv1, lv2]

    with patch("dissect.util.stream.MappingStream.add") as mock_add:
        streams = list(target_bare.scrape.create_streams(encrypted=True, lvm=True))

        assert len(streams) == 1
        assert call(0, 400, lv2, 0) in mock_add.call_args_list


def test_create_streams_lvm_shared_pv(target_bare: Target) -> None:
    """Test two LVs sharing the same Physical Volume (VG)."""
    target_bare.add_plugin(ScrapePlugin)

    disk = MockFactory.create_disk(size=1000)
    pv_part = MockFactory.create_volume("pv_part", disk, offset=0, size=1000)

    # Both LVs reside on the same PV
    lv1 = MockFactory.make_lvm("lv1", [pv_part], size=500)
    lv2 = MockFactory.make_lvm("lv2", [pv_part], size=500)

    target_bare.disks.add(disk)
    target_bare.volumes.entries = [pv_part, lv1, lv2]

    with patch("dissect.util.stream.MappingStream.add") as mock_add:
        streams = list(target_bare.scrape.create_streams(lvm=True))

        assert len(streams) == 2  # One for each LV

        # Verify LVs exist
        assert call(0, 500, lv1, 0) in mock_add.call_args_list
        assert call(0, 500, lv2, 0) in mock_add.call_args_list


def test_find(target_bare: Target) -> None:
    target_bare.add_plugin(ScrapePlugin)

    buf = (b"\x00" * 1024 * 64) + (b"ABCD" + b"\x00" * ((1024 * 4) - 4)) + (b"\x00" * 1024 * 60)
    mock_disk = RawContainer(io.BytesIO(buf))
    target_bare.disks.add(mock_disk)

    mock_progress = Mock()
    for disk, stream, needle, offset, match in target_bare.scrape.find(b"ABCD", progress=mock_progress):
        assert disk.size == 1024 * 128
        assert stream.size == 1024 * 128
        assert needle == b"ABCD"
        assert offset == 1024 * 64
        assert not match  # only for regex matches

    for i in range(0, 1024 * 128, 8192):
        mock_progress.assert_any_call(mock_disk, i, 1024 * 128)


def test_find_needles_in_contiguous_regions(target_bare: Target) -> None:
    """Test finding a needle overlapping two contiguous regions."""
    needle = b"NEEDLE"
    buffer = b"A" * 100 + needle + b"B" * 100
    half = len(buffer) // 2

    disk = RawContainer(io.BytesIO(buffer))
    disk.size = len(buffer)

    # First volume covers first half
    volume1 = io.BytesIO(buffer[:half])
    volume1.disk = disk
    volume1.offset = 0
    volume1.size = half

    # Second volume covers second half
    volume2 = io.BytesIO(buffer[half:])
    volume2.disk = disk
    volume2.offset = half
    volume2.size = half

    disk.vs = Mock()  # Add a mock 'vs' attribute
    disk.vs.volumes = [volume1, volume2]
    target_bare.disks.entries = [disk]
    target_bare.add_plugin(ScrapePlugin)

    found = list(target_bare.scrape.find(needle))
    # Only check offsets and needle, not disk or stream
    assert [(n, offset) for (_, _, n, offset, _) in found] == [
        (needle, 100),
    ]


def test_find_needle_in_lvm_and_other_volume(target_bare: Target) -> None:
    """Test finding needles in non-contiguous regions."""

    # Layout: [---vol1(LVM)---][---volB---][---rest---]
    needle = b"NEEDLE"
    disk_size = 4096 * 4

    # Create disk buffer
    buf = bytearray(b"\x00" * disk_size)

    # Place needle in vol1 (LVM)
    vol1_offset = 512
    vol1_size = 1024
    needle1_offset = 100
    buf[vol1_offset + needle1_offset : vol1_offset + needle1_offset + len(needle)] = needle

    # Place needle in volB
    volB_offset = 2048
    volB_size = 512
    needle2_offset = volB_offset + 50
    buf[needle2_offset : needle2_offset + len(needle)] = needle

    disk = RawContainer(io.BytesIO(buf))
    disk.size = disk_size

    # Create vol1 (LVM base volume)
    vol1 = io.BytesIO(buf[vol1_offset : vol1_offset + vol1_size])
    vol1.disk = disk
    vol1.offset = vol1_offset
    vol1.size = vol1_size

    # Create volB (regular volume)
    volB = io.BytesIO(buf[volB_offset : volB_offset + volB_size])
    volB.disk = disk
    volB.offset = volB_offset
    volB.size = volB_size

    # Attach volumes to disk
    disk.vs = Mock()
    disk.vs.volumes = [vol1, volB]

    # Create LVM logical volume using vol1 as base
    lvm_lv = io.BytesIO(buf[vol1_offset : vol1_offset + vol1_size])
    lvm_lv.disk = [disk]
    lvm_lv.offset = 0
    lvm_lv.size = vol1_size

    # Create a mock LVM volume system and assign to the logical volume
    lvm_vs = Mock(spec=LogicalVolumeSystem)
    lvm_dev = Mock(spec=LVM2Device, fh=vol1)
    lvm_vs.fh = [lvm_dev]
    lvm_lv.vs = lvm_vs

    # Add LVM logical volume to target volumes
    target_bare.disks.entries = [disk]
    target_bare.volumes.entries = [lvm_lv]
    target_bare.add_plugin(ScrapePlugin)

    # Find the needle
    found = list(target_bare.scrape.find(needle))
    # Should find the needle in both the LVM logical volume (disk2) and in volB (disk1)
    assert [(n, offset) for (_, _, n, offset, _) in found] == [(needle, needle2_offset), (needle, needle1_offset)]
