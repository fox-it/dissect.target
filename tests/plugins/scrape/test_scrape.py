from __future__ import annotations

import io
from typing import TYPE_CHECKING
from unittest.mock import Mock, call, patch

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

    mock_disk.vs.volumes = [mock_volume_1, mock_volume_2]

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

    mock_encrypted_volume = Mock(name="mock_encrypted_volume")
    mock_encrypted_volume.disk = mock_volume_1
    mock_encrypted_volume.offset = 1024
    mock_encrypted_volume.size = 1024 * 8
    mock_encrypted_volume.vs = Mock(spec=EncryptedVolumeSystem)

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
                call(1024 * 9, 1024, mock_disk, 1024 * 9),
                call(1024 * 18, 1024 * 46, mock_disk, 1024 * 18),
                call(0, 1024 * 16, mock_lvm_volume, 0),
            ]
        )

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
    for disk, stream, needle, offset in target_bare.scrape.find(b"ABCD", progress=mock_progress):
        assert disk.size == 1024 * 128
        assert stream.size == 1024 * 128
        assert needle == b"ABCD"
        assert offset == 1024 * 64

    for i in range(0, 1024 * 128, 8192):
        mock_progress.assert_any_call(mock_disk, i, 1024 * 128)
