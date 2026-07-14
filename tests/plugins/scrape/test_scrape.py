from __future__ import annotations

import gzip
import io
from typing import TYPE_CHECKING
from unittest.mock import Mock, call, patch

import pytest

from dissect.target.containers.raw import RawContainer
from dissect.target.helpers import keychain
from dissect.target.helpers.scrape import find_needles
from dissect.target.plugins.scrape.scrape import ScrapePlugin
from dissect.target.target import Target
from dissect.target.volume import EncryptedVolumeSystem, LogicalVolumeSystem
from tests._utils import absolute_path

try:
    from dissect.target.volumes.luks import LUKSVolumeSystem

    HAS_LUKS = True
except ImportError:
    HAS_LUKS = False

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.util.stream import MappingStream

    from dissect.target.container import Container
    from dissect.target.volume import Volume


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
    def create_raw_disk(name: str, volume_name: str, size: int = 100_000) -> tuple[Mock, Mock]:
        raw_disk = Mock(name=name)
        raw_disk.size = size
        raw_disk.vs = None  # No volume system
        volume = MockFactory.create_volume(volume_name, raw_disk, offset=0, size=size)
        return raw_disk, volume

    @staticmethod
    def create_volume(name: str, backing_disk: Mock, offset: int, size: int) -> Mock:
        vol = Mock(name=name)
        vol.disk = [backing_disk]  # Backing disk(s) are always a list
        vol.offset = offset
        vol.size = size
        vol.vs = None  # Default to no file system

        # Add to backing disk's VS list (mimicking a partition table)
        if getattr(backing_disk, "vs", None):
            backing_disk.vs.volumes.append(vol)

        return vol

    @staticmethod
    def make_encrypted(volume: Mock, decrypted_vol_name: str) -> Mock:
        """Turns a volume into a LUKS container and returns the decrypted volume."""
        decrypted = Mock(name=decrypted_vol_name)
        decrypted.size = volume.size - 64  # Header overhead
        decrypted.offset = 0
        decrypted.vs = None
        decrypted.disk = volume.disk  # Points to physical disk

        decrypted.vs = Mock(spec=EncryptedVolumeSystem)
        decrypted.vs.fhs = [volume]
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

        lv.vs = Mock(spec=LogicalVolumeSystem)
        lv.vs.fhs = list(backing_volumes)
        return lv


def test_create_streams_two_ordinary_volumes(target_bare: Target) -> None:
    """Test scrape streams for a standard physical disk with two partitions and gaps."""
    target_bare.add_plugin(ScrapePlugin)

    # Setup
    disk = MockFactory.create_disk(size=100)
    vol1 = MockFactory.create_volume("vol1", disk, offset=10, size=20)
    vol2 = MockFactory.create_volume("vol2", disk, offset=50, size=20)

    target_bare.disks.add(disk)

    with patch("dissect.util.stream.MappingStream.add") as mock_add:
        streams = list(target_bare.scrape.create_streams())

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
    """Test Case 3: Nested LVM -> LUKS -> LVM."""
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


def test_create_streams_raid_spanning_disks(target_bare: Target) -> None:
    """Test scrape streams for a RAID array (e.g. md/ddf) spanning multiple physical disks.

    RAID volume systems are ``LogicalVolumeSystem`` subclasses, so they resolve through the same
    layer-resolution path as LVM. The member volume on each physical disk should be consumed and a
    single reconstructed stream should be yielded for the assembled array.
    """
    target_bare.add_plugin(ScrapePlugin)

    # Two physical disks, each holding one RAID member volume spanning the whole disk
    disk_a = MockFactory.create_disk("raid_disk_a", size=1000)
    member_a = MockFactory.create_volume("member_a", disk_a, offset=0, size=1000)

    disk_b = MockFactory.create_disk("raid_disk_b", size=1000)
    member_b = MockFactory.create_volume("member_b", disk_b, offset=0, size=1000)

    # The reconstructed RAID array spans both members (LogicalVolumeSystem, like md/ddf)
    raid = MockFactory.make_lvm("md0", [member_a, member_b], size=1800)

    target_bare.disks = {disk_a, disk_b}
    target_bare.volumes.entries = [raid]

    with patch("dissect.util.stream.MappingStream.add") as mock_add:
        streams = list(target_bare.scrape.create_streams(lvm=True))

        calls = mock_add.call_args_list

        # A single reconstructed stream for the assembled array
        assert len(streams) == 1
        assert streams[0][0] == raid
        assert call(0, 1800, raid, 0) in calls

        # Both raw members are consumed, not scraped separately
        assert call(0, 1000, member_a, 0) not in calls
        assert call(0, 1000, member_b, 0) not in calls


def test_create_streams_raid_spanning_disks_all(target_bare: Target) -> None:
    """Test that ``all=True`` keeps the raw RAID members in addition to the reconstructed array."""
    target_bare.add_plugin(ScrapePlugin)

    disk_a = MockFactory.create_disk("raid_disk_a", size=1000)
    member_a = MockFactory.create_volume("member_a", disk_a, offset=0, size=1000)

    disk_b = MockFactory.create_disk("raid_disk_b", size=1000)
    member_b = MockFactory.create_volume("member_b", disk_b, offset=0, size=1000)

    raid = MockFactory.make_lvm("md0", [member_a, member_b], size=1800)

    target_bare.disks = {disk_a, disk_b}
    target_bare.volumes.entries = [raid]

    with patch("dissect.util.stream.MappingStream.add") as mock_add:
        list(target_bare.scrape.create_streams(lvm=True, all=True))

        calls = mock_add.call_args_list

        # Reconstructed array is present
        assert call(0, 1800, raid, 0) in calls

        # Raw members are retained as well
        assert call(0, 1000, member_a, 0) in calls
        assert call(0, 1000, member_b, 0) in calls


@pytest.mark.parametrize(
    ("encrypted", "all_flag", "expect_raw", "expect_decrypted", "expect_inplace"),
    [
        (False, False, True, False, False),  # Case 1: Ignore encryption
        (True, False, False, True, True),  # Case 2: Standard decryption (Swap)
        (True, True, True, True, False),  # Case 3: Keep all artifacts
    ],
)
def test_create_streams_encrypted(
    target_bare: Target, encrypted: bool, all_flag: bool, expect_raw: bool, expect_decrypted: bool, expect_inplace: bool
) -> None:
    target_bare.add_plugin(ScrapePlugin)

    disk = MockFactory.create_disk(size=2000)
    # The raw partition at offset 100
    partition = MockFactory.create_volume("part_luks", disk, offset=100, size=1000)
    # The logical decrypted volume
    decrypted = MockFactory.make_encrypted(partition, "decrypted_vol")

    target_bare.disks.add(disk)
    target_bare.volumes.entries = [decrypted]

    with patch("dissect.util.stream.MappingStream.add") as mock_add:
        # Run the method with the parameterized flags
        list(target_bare.scrape.create_streams(encrypted=encrypted, all=all_flag))

        calls = mock_add.call_args_list
        # Check for the Raw Partition # It should appear at offset 100 on the disk
        raw_call = call(100, 1000, partition, 0)
        if expect_raw:
            assert raw_call in calls, "Expected raw encrypted partition to be visible."
        else:
            assert raw_call not in calls, "Expected raw encrypted partition to be hidden/replaced."

        # Check for the Decrypted Volume
        found_decrypted = False
        for call_args in [call.args for call in calls]:
            # c.args = (offset, size, source, source_offset)
            if call_args[2] == decrypted:
                found_decrypted = True
                mapped_offset = call_args[0]

                if expect_inplace:
                    # In-place replacement: Must be at partition's offset (100)
                    assert mapped_offset == 100, "Expected in-place replacement (offset 100)"
                else:
                    # New Stream: Must be at offset 0 (start of new stream)
                    assert mapped_offset == 0, "Expected new stream (offset 0)"

        assert expect_decrypted == found_decrypted


@pytest.mark.parametrize(
    ("lvm", "all_flag", "expect_pv", "expect_lv"),
    [
        (False, False, True, False),  # Case 1: Ignore LVM
        (True, False, False, True),  # Case 2: Standard LVM (Consume PV)
        (True, True, True, True),  # Case 3: Keep all artifacts
    ],
)
def test_create_streams_lvm(target_bare: Target, lvm: bool, all_flag: bool, expect_pv: bool, expect_lv: bool) -> None:
    """Test scrape streams for LVM volumes with various flags."""
    target_bare.add_plugin(ScrapePlugin)

    disk = MockFactory.create_disk(size=2000)
    # The raw PV partition
    pv_part = MockFactory.create_volume("part_pv", disk, offset=100, size=1000)
    # The logical volume residing on that PV
    lv = MockFactory.make_lvm("lv_root", [pv_part], size=800)

    target_bare.disks.add(disk)
    target_bare.volumes.entries = [lv]

    with patch("dissect.util.stream.MappingStream.add") as mock_add:
        list(target_bare.scrape.create_streams(lvm=lvm, all=all_flag))

        calls = mock_add.call_args_list

        # 1. Check for Raw PV Partition
        pv_call = call(100, 1000, pv_part, 0)
        if expect_pv:
            assert pv_call in calls, "Expected Raw PV partition to be visible."
        else:
            assert pv_call not in calls, "Expected Raw PV to be consumed (removed)."

        # 2. Check for Logical Volume
        # LVM volumes are *always* new streams (offset 0), never in-place replacements
        lv_call = call(0, lv.size, lv, 0)
        if expect_lv:
            assert lv_call in calls, "Expected Logical Volume stream to be visible."
        else:
            assert lv_call not in calls, "Expected Logical Volume stream to be hidden."


def test_create_streams_two_raw_disks(target_bare: Target) -> None:
    """Test Scenario: Two separate raw disks (no partition table)."""
    target_bare.add_plugin(ScrapePlugin)

    disk_a, vol_a = MockFactory.create_raw_disk("disk_a", "vol_a_whole", size=1000)
    disk_b, vol_b = MockFactory.create_raw_disk("disk_b", "vol_b_whole", size=2000)

    target_bare.disks = {disk_a, disk_b}
    target_bare.volumes.entries = [vol_a, vol_b]

    with patch("dissect.util.stream.MappingStream.add") as mock_add:
        streams = list(target_bare.scrape.create_streams())

        assert len(streams) == 2

        # Inspect calls to MappingStream.add(offset, size, source, source_offset)
        all_calls = mock_add.call_args_list

        assert call(0, 1000, vol_a, 0) in all_calls
        assert call(0, 2000, vol_b, 0) in all_calls


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

    for i in range(0, 1024 * 128, io.DEFAULT_BUFFER_SIZE):
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
    volume1.disk = [disk]
    volume1.offset = 0
    volume1.size = half

    # Second volume covers second half
    volume2 = io.BytesIO(buffer[half:])
    volume2.disk = [disk]
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
    vol1.disk = [disk]
    vol1.offset = vol1_offset
    vol1.size = vol1_size

    # Create volB (regular volume)
    volB = io.BytesIO(buf[volB_offset : volB_offset + volB_size])
    volB.disk = [disk]
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
    lvm_vs.fhs = [vol1]
    lvm_lv.vs = lvm_vs

    # Add LVM logical volume to target volumes
    target_bare.disks.entries = [disk]
    target_bare.volumes.entries = [lvm_lv]
    target_bare.add_plugin(ScrapePlugin)

    # Find the needle
    found = list(target_bare.scrape.find(needle))
    # Should find the needle in both the LVM logical volume (disk2) and in volB (disk1)
    assert [(n, offset) for (_, _, n, offset, _) in found] == [(needle, needle2_offset), (needle, needle1_offset)]


# Integration tests

MARKER = b"wow it worked"

# Fixed passphrase used by tests/_tools/make_luks_lvm.sh to create the LUKS keyslot.
LUKS_LVM_PASSPHRASE = "password1234"
LUKS_LVM_FIXTURE = absolute_path("_data/volumes/luks_lvm/luks-lvm.bin.gz")


def _logical_volumes(target: Target) -> list[Volume]:
    return [vol for vol in target.volumes if isinstance(vol.vs, LogicalVolumeSystem)]


def _find_in_streams(
    streams: Iterator[tuple[Container | Volume, list[tuple[int, MappingStream]]]], needle: bytes
) -> list[tuple[Container | Volume, int]]:
    """Collect ``(disk, physical_offset)`` tuples for a needle across all given scrape streams."""
    hits = []
    for disk, disk_streams in streams:
        for physical_offset, stream in disk_streams:
            for _, offset, _ in find_needles(stream, [needle]):
                hits.append((disk, physical_offset + offset))
    return hits


def test_scrape_ddf_raid() -> None:
    """Scraping a 2-disk DDF RAID1 array should yield a reconstructed stream for the assembled volume."""
    with (
        gzip.open(absolute_path("_data/volumes/ddf/ddf-disk0.bin.gz"), "rb") as fh0,
        gzip.open(absolute_path("_data/volumes/ddf/ddf-disk1.bin.gz"), "rb") as fh1,
    ):
        t = Target()
        t.disks.add(RawContainer(fh0))
        t.disks.add(RawContainer(fh1))
        t.apply()
        t.add_plugin(ScrapePlugin)

        # The known marker should be found through the reconstructed array, which proves it was scraped
        # as its own stream. The scraper reports offsets in the reconstructed volume's own coordinate
        # space, so reading it back at that offset should land exactly on the marker.
        raid_hits = [
            (disk, offset)
            for disk, _, needle, offset, _ in t.scrape.find(MARKER)
            if needle == MARKER and isinstance(disk.vs, LogicalVolumeSystem)
        ]
        assert raid_hits
        for disk, offset in raid_hits:
            disk.seek(offset)
            assert disk.read(len(MARKER)) == MARKER


def test_scrape_md_nested_lvm() -> None:
    """Scraping an MD RAID disk with a nested LVM should find data through the reconstructed logical volume."""
    with gzip.open(absolute_path("_data/volumes/md/md-nested.bin.gz"), "rb") as fh:
        t = Target()
        t.disks.add(RawContainer(fh))
        t.apply()
        t.add_plugin(ScrapePlugin)

        # The marker is stored in the filesystem on the reconstructed logical volume. The reported
        # offset should point at the marker within that logical volume's own coordinate space.
        lv_hits = [
            (disk, offset)
            for disk, _, needle, offset, _ in t.scrape.find(MARKER)
            if needle == MARKER and isinstance(disk.vs, LogicalVolumeSystem)
        ]
        assert lv_hits
        for disk, offset in lv_hits:
            disk.seek(offset)
            assert disk.read(len(MARKER)) == MARKER


@pytest.mark.skipif(not HAS_LUKS, reason="requires dissect.fve")
def test_scrape_luks_lvm() -> None:
    """Scraping a LUKS-encrypted disk with a nested LVM should resolve decryption and the logical volume.

    Layout: disk (GPT) -> partition -> LUKS -> LVM -> ext2 -> file.txt. With the passphrase registered,
    the scraper should map the decrypted volume in place at the LUKS partition offset and expose the
    reconstructed logical volume as its own stream containing the marker.
    """
    with patch.object(keychain, "KEYCHAIN", []):
        keychain.register_key(keychain.KeyType.PASSPHRASE, LUKS_LVM_PASSPHRASE, provider=LUKSVolumeSystem.__type__)

        with gzip.open(LUKS_LVM_FIXTURE, "rb") as fh:
            t = Target()
            t.disks.add(RawContainer(fh))
            t.apply()
            t.add_plugin(ScrapePlugin)

            # The LUKS layer should have produced exactly one decrypted volume and one logical volume.
            encrypted = [vol for vol in t.volumes if isinstance(vol.vs, EncryptedVolumeSystem)]
            assert len(encrypted) == 1
            decrypted = encrypted[0]

            # The encrypted partition backing the decrypted volume sits at a non-zero offset on disk.
            partition = decrypted.vs.fhs[0]
            assert partition.offset > 0

            # With decryption but without LVM reconstruction, the marker is reachable in the decrypted
            # volume, mapped in place on the disk at the LUKS partition offset. The physical offset the
            # scraper reports should equal the partition offset plus the marker's offset within the
            # decrypted volume.
            decrypted_hits = _find_in_streams(t.scrape.create_streams(encrypted=True, lvm=False), MARKER)
            assert decrypted_hits
            for _, offset in decrypted_hits:
                assert offset >= partition.offset
                decrypted.seek(offset - partition.offset)
                assert decrypted.read(len(MARKER)) == MARKER

            # With LVM reconstruction, the marker is found through the reconstructed logical volume, and
            # the reported offset points at the marker within that logical volume.
            lv = _logical_volumes(t)[0]

            lv_offsets = [
                offset for disk, _, needle, offset, _ in t.scrape.find(MARKER) if needle == MARKER and disk is lv
            ]
            assert lv_offsets
            for offset in lv_offsets:
                lv.seek(offset)
                assert lv.read(len(MARKER)) == MARKER
