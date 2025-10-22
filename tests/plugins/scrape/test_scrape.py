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


def test_create_streams(target_bare: Target) -> None:
    target_bare.add_plugin(ScrapePlugin)

    streams = list(target_bare.scrape.create_streams())
    assert len(streams) == 0

    mock_disk = Mock(name="mock_disk")
    mock_disk.size = 1024 * 64

    mock_volume_1 = Mock(name="mock_volume_1")
    mock_volume_1.disk = mock_disk
    mock_volume_1.offset = 1024
    mock_volume_1.size = 1024 * 8
    mock_volume_2 = Mock(name="mock_volume_2")
    mock_volume_2.disk = mock_disk
    mock_volume_2.offset = 1024 * 10
    mock_volume_2.size = 1024 * 8

    mock_disk.vs.volumes = [mock_volume_2, mock_volume_1]  # Test out-of-order volumes

    target_bare.disks.add(mock_disk)

    expected_base = [
        call(0, 1024, mock_disk, 0),
        call(1024, 1024 * 8, mock_volume_1, 0),
        call(1024 * 9, 1024, mock_disk, 1024 * 9),
        call(1024 * 10, 1024 * 8, mock_volume_2, 0),
        call(1024 * 18, 1024 * 46, mock_disk, 1024 * 18),
    ]

    with patch("dissect.util.stream.MappingStream.add") as mock_add:
        streams = list(target_bare.scrape.create_streams())
        mock_add.assert_has_calls(expected_base)

        assert len(streams) == 1
        # Get the number of streams for each disk
        stream_counts = [len(streams) for _, streams in streams]
        assert stream_counts == [1]

    mock_encrypted_volume = Mock(name="mock_encrypted_volume")
    mock_encrypted_volume.disk = mock_disk
    mock_encrypted_volume.offset = 1024
    mock_encrypted_volume.size = 1024 * 8
    mock_encrypted_volume.vs = Mock(spec=EncryptedVolumeSystem, fh=mock_encrypted_volume)

    target_bare.volumes.entries = [mock_encrypted_volume]

    with patch("dissect.util.stream.MappingStream.add") as mock_add:
        streams = list(target_bare.scrape.create_streams(encrypted=False))
        mock_add.assert_has_calls(expected_base)

        mock_add.reset_mock()

        streams = list(target_bare.scrape.create_streams(encrypted=True))
        mock_add.assert_has_calls(
            [
                call(0, 1024, mock_disk, 0),
                call(1024, 1024 * 8, mock_encrypted_volume, 0),
                call(1024 * 9, 1024, mock_disk, 1024 * 9),
                call(1024 * 10, 1024 * 8, mock_volume_2, 0),
                call(1024 * 18, 1024 * 46, mock_disk, 1024 * 18),
            ]
        )

        assert len(streams) == 1
        # Get the number of streams for each disk
        stream_counts = [len(streams) for _, streams in streams]
        assert stream_counts == [1]

        mock_add.reset_mock()

        streams = list(target_bare.scrape.create_streams(encrypted=True, all=True))
        mock_add.assert_has_calls(
            [
                call(0, 1024, mock_disk, 0),
                call(1024, 1024 * 8, mock_volume_1, 0),
                call(1024 * 9, 1024, mock_disk, 1024 * 9),
                call(1024 * 10, 1024 * 8, mock_volume_2, 0),
                call(1024 * 18, 1024 * 46, mock_disk, 1024 * 18),
                call(0, 1024 * 8, mock_encrypted_volume, 0),
            ]
        )

        assert len(streams) == 2
        # Get the number of streams for each disk
        stream_counts = [len(streams) for _, streams in streams]
        assert stream_counts == [1, 1]

    mock_lvm_volume = Mock(name="mock_lvm_volume")
    mock_lvm_volume.size = 1024 * 16
    mock_lvm_volume.disk = [mock_volume_1, mock_volume_2]
    mock_lvm_volume.vs = Mock(spec=LogicalVolumeSystem)

    target_bare.volumes.entries = [mock_lvm_volume]

    with patch("dissect.util.stream.MappingStream.add") as mock_add:
        streams = list(target_bare.scrape.create_streams(lvm=False))
        mock_add.assert_has_calls(expected_base)

        mock_add.reset_mock()

        streams = list(target_bare.scrape.create_streams(lvm=True))
        mock_add.assert_has_calls(
            [
                call(0, 1024, mock_disk, 0),
                call(0, 1024, mock_disk, 1024 * 9),
                call(0, 1024 * 46, mock_disk, 1024 * 18),
                call(0, 1024 * 16, mock_lvm_volume, 0),
            ]
        )
        assert len(streams) == 2
        # Get the number of streams for each disk
        stream_counts = [len(streams) for _, streams in streams]
        assert stream_counts == [3, 1]
        # Get the offsets for the first disk's streams
        first_disk_offsets = [streams[0][1][i][0] for i in range(3)]
        assert first_disk_offsets == [0, 1024 * 9, 1024 * 18]
        # Get the offset for the second disk's only stream
        second_disk_offsets = [streams[1][1][i][0] for i in range(1)]
        assert second_disk_offsets == [0]

        mock_add.reset_mock()

        streams = list(target_bare.scrape.create_streams(lvm=True, all=True))
        mock_add.assert_has_calls(
            [
                call(0, 1024, mock_disk, 0),
                call(1024, 1024 * 8, mock_volume_1, 0),
                call(1024 * 9, 1024, mock_disk, 1024 * 9),
                call(1024 * 10, 1024 * 8, mock_volume_2, 0),
                call(1024 * 18, 1024 * 46, mock_disk, 1024 * 18),
                call(0, 1024 * 16, mock_lvm_volume, 0),
            ]
        )


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
