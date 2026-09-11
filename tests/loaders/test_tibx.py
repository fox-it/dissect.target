from __future__ import annotations

import struct
import sys
import urllib.parse
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from dissect.archive.tibx.c_tibx import (
    ENVELOPE_SIZE,
    LSB_FIXED_SIZE,
    LSB_MEMTREE_OFFSET,
    PAGE_MARKER,
    PAGE_SIZE,
    SEGMENT_HEADER_OFFSET,
    SEGMENT_PAYLOAD_OFFSET,
    TLV_DIRECTORY_OFFSET,
    TLV_SLOT_COUNT,
    c_tibx,
)
from dissect.archive.tibx.exception import InvalidPasswordError
from dissect.archive.tibx.page import page_crc32c

from dissect.target.exceptions import LoaderError
from dissect.target.helpers import keychain
from dissect.target.loaders.tibx import TibxLoader
from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


def _build_fat12_image(content: bytes) -> bytes:
    """A minimal 64-sector FAT12 image with one root file holding ``content``."""
    bps, spc, reserved, nfats, root_entries, fat_sectors, total = 512, 1, 1, 1, 16, 1, 64
    img = bytearray(total * bps)
    img[0:3] = b"\xeb\x3c\x90"
    img[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", img, 0x0B, bps)
    img[0x0D] = spc
    struct.pack_into("<H", img, 0x0E, reserved)
    img[0x10] = nfats
    struct.pack_into("<H", img, 0x11, root_entries)
    struct.pack_into("<H", img, 0x13, total)
    img[0x15] = 0xF8
    struct.pack_into("<H", img, 0x16, fat_sectors)
    img[0x36:0x3E] = b"FAT12   "
    img[0x1FE:0x200] = b"\x55\xaa"
    fat_offset = reserved * bps
    img[fat_offset : fat_offset + 6] = bytes([0xF8, 0xFF, 0xFF, 0xFF, 0x0F, 0x00])
    root_offset = (reserved + nfats * fat_sectors) * bps
    entry = bytearray(32)
    entry[0:11] = b"HELLO   TXT"
    entry[0x0B] = 0x20
    struct.pack_into("<H", entry, 0x1A, 2)
    struct.pack_into("<I", entry, 0x1C, len(content))
    img[root_offset : root_offset + 32] = entry
    first_data = reserved + nfats * fat_sectors + (root_entries * 32 + bps - 1) // bps
    img[first_data * bps : first_data * bps + len(content)] = content
    return bytes(img)


def _page(page_type: int, content: dict[int, bytes]) -> bytes:
    """A CRC-correct page of ``page_type`` with ``content`` placed at the given offsets."""
    page = bytearray(PAGE_SIZE)
    for offset, data in content.items():
        page[offset : offset + len(data)] = data
    header = c_tibx.page_header(marker=PAGE_MARKER, type=page_type)
    page[:ENVELOPE_SIZE] = header.dumps()
    header.crc32c = page_crc32c(bytes(page))
    page[:ENVELOPE_SIZE] = header.dumps()
    return bytes(page)


def _lsb(key_length: int, value_length: int, cells: list[tuple[bytes, bytes]]) -> bytes:
    """An L-SB whose mem-tree holds ``cells``: one compact group of live records."""
    stream = c_tibx.lsm_cell_group_header(count=len(cells), alive=(1 << len(cells)) - 1).dumps()
    stream += b"".join(key + value for key, value in cells)

    record = bytearray(LSB_FIXED_SIZE)
    superblock = c_tibx.lsm_superblock(
        magic=b"L-SB", format_version=1, ctree_max_minus_2=8, seq=1, key_length=key_length, value_length=value_length
    )
    record[: len(c_tibx.lsm_superblock)] = superblock.dumps()
    memtree = c_tibx.lsm_memtree_header(node_count=len(cells), extra_len=len(stream))
    record[LSB_MEMTREE_OFFSET : LSB_MEMTREE_OFFSET + len(c_tibx.lsm_memtree_header)] = memtree.dumps()
    return bytes(record) + stream


def _build_tibx_archive(streams: list[tuple[int, int, bytes]], slices: list[int] | None = None) -> bytes:
    """Build a synthetic TIBX archive holding ``streams`` of ``(volume_id, slice_id, data)``.

    Page 0 is the ARCH header, with the data_map and segment_map (and, given ``slices``,
    the slices tree) as LSM mem-trees; each stream follows as one zstd segment page.
    """
    if sys.version_info >= (3, 14):
        from compression import zstd  # novermin
    else:
        from backports import zstd

    dm_cells, sm_cells, segments = [], [], []
    for index, (volume_id, slice_id, data) in enumerate(streams):
        segment_id = 100 + index
        dm_key = c_tibx.data_map_key(
            volume_id=volume_id, source_offset=0, extent_length=len(data), slice_id=slice_id, extent_id=index + 1
        )
        dm_cells.append((dm_key.dumps(), c_tibx.data_map_value(segment_id=segment_id, extent_index=0xFFFF).dumps()))
        sm_value = c_tibx.segment_map_value(page_count=(1).to_bytes(4, "little"), page_offset=1 + index)
        sm_cells.append((c_tibx.segment_map_key(segment_id=segment_id).dumps(), sm_value.dumps()))

        blob = zstd.compress(data)
        header = c_tibx.segment_header(magic=b"SG", version=1, length=len(data), zlength=len(blob), compression=0x0300)
        segments.append(
            _page(c_tibx.PageType.DATA, {SEGMENT_HEADER_OFFSET: header.dumps(), SEGMENT_PAYLOAD_OFFSET: blob})
        )

    slots = {1: _lsb(31, 10, sorted(dm_cells)), 2: _lsb(8, 32, sm_cells)}
    if slices:
        records = [
            (
                c_tibx.slice_key(slice_id=slice_id).dumps(),
                c_tibx.slice_record(guid=bytes([slice_id]) * 16, created_ms=slice_id, modified_ms=slice_id).dumps(),
            )
            for slice_id in slices
        ]
        slots[5] = _lsb(len(c_tibx.slice_key), len(c_tibx.slice_record), records)

    directory = bytearray()
    for index in range(TLV_SLOT_COUNT):
        payload = slots.get(index, b"")
        directory += c_tibx.tlv_header(length=len(payload)).dumps() + payload
        directory += b"\x00" * (-len(directory) % 4)

    body = c_tibx.arch_header(
        magic=b"ARCH",
        header_size=TLV_DIRECTORY_OFFSET + len(directory),
        header_version=8,
        created_ms=1000,
        modified_ms=2000,
        archive_uuid=b"\xab" * 16,
    )
    arch = _page(
        c_tibx.PageType.ARCH,
        {ENVELOPE_SIZE: body.dumps(), ENVELOPE_SIZE + TLV_DIRECTORY_OFFSET: bytes(directory)},
    )
    return arch + b"".join(segments)


def _loader(path: Path, query: str = "") -> TibxLoader:
    return TibxLoader(path, parsed_path=urllib.parse.urlparse(f"tibx://{path.name}?{query}"))


def _read_hello(loader: TibxLoader) -> bytes:
    target = Target()
    loader.map(target)
    target.apply()
    return target.filesystems[0].path("/HELLO.TXT").read_bytes()


FILE_CONTENT = b"hello from inside a tibx backup"


@pytest.fixture
def fat_archive(tmp_path: Path) -> Path:
    path = tmp_path / "backup.tibx"
    path.write_bytes(_build_tibx_archive([(10, 2, _build_fat12_image(FILE_CONTENT))]))
    return path


@pytest.fixture
def chain_archive(tmp_path: Path) -> Path:
    """A full backup (slice 2) and an incremental (slice 3) that rewrote the volume."""
    path = tmp_path / "chain.tibx"
    streams = [(10, 2, _build_fat12_image(b"full backup")), (10, 3, _build_fat12_image(b"incremental"))]
    path.write_bytes(_build_tibx_archive(streams, slices=[2, 3]))
    return path


@pytest.fixture
def _registered_loader() -> Iterator[None]:
    from dissect.target import loader as loader_registry

    loader_registry.LOADERS.append(TibxLoader)
    loader_registry.LOADERS_BY_SCHEME["tibx"] = TibxLoader
    yield
    loader_registry.LOADERS.remove(TibxLoader)
    loader_registry.LOADERS_BY_SCHEME.pop("tibx")


def test_detect(fat_archive: Path, tmp_path: Path) -> None:
    assert TibxLoader.detect(fat_archive)

    wrong_suffix = tmp_path / "backup.vbk"
    wrong_suffix.write_bytes(fat_archive.read_bytes())
    assert not TibxLoader.detect(wrong_suffix)

    wrong_magic = tmp_path / "other.tibx"
    wrong_magic.write_bytes(b"\x00" * 0x1000)
    assert not TibxLoader.detect(wrong_magic)

    truncated = tmp_path / "truncated.tibx"
    truncated.write_bytes(fat_archive.read_bytes()[:16])
    assert not TibxLoader.detect(truncated)

    assert not TibxLoader.detect(tmp_path / "missing.tibx")


def test_map_volume_and_filesystem(fat_archive: Path) -> None:
    target = Target()
    TibxLoader(fat_archive).map(target)

    assert len(target.volumes) == 1
    volume = next(iter(target.volumes))
    assert volume.size == 64 * 512

    target.apply()
    assert len(target.filesystems) == 1
    filesystem = target.filesystems[0]
    assert filesystem.__type__ == "fat"
    assert filesystem.path("/HELLO.TXT").read_bytes() == FILE_CONTENT


def test_metadata_streams_are_not_mapped(tmp_path: Path) -> None:
    # Acronis keys its own metadata by volume id just like a partition; only the
    # partition may become a volume
    path = tmp_path / "backup.tibx"
    streams = [(10, 2, _build_fat12_image(FILE_CONTENT)), (3, 2, b'<?xml version="1.0"?><metainfo/>')]
    path.write_bytes(_build_tibx_archive(streams))

    target = Target()
    TibxLoader(path).map(target)
    assert [volume.name for volume in target.volumes] == ["tibx_a"]


@pytest.mark.usefixtures("_registered_loader")
def test_target_open_selects_loader(fat_archive: Path) -> None:
    target = Target.open(fat_archive)
    assert isinstance(target._loader, TibxLoader)
    assert len(target.filesystems) == 1


def test_latest_recovery_point_is_default(chain_archive: Path) -> None:
    assert _read_hello(TibxLoader(chain_archive)) == b"incremental"


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("recovery-point=0", b"full backup"),
        ("recovery-point=1", b"incremental"),
        ("recovery-point=oldest", b"full backup"),
        ("recovery-point=latest", b"incremental"),
    ],
)
def test_select_recovery_point(chain_archive: Path, query: str, expected: bytes) -> None:
    assert _read_hello(_loader(chain_archive, query)) == expected


@pytest.mark.parametrize("value", ["2", "-1", "bogus"])
def test_invalid_recovery_point(chain_archive: Path, value: str) -> None:
    with pytest.raises(LoaderError, match="Invalid recovery point"):
        _loader(chain_archive, f"recovery-point={value}")


def test_recovery_point_without_recorded_backups(fat_archive: Path) -> None:
    with pytest.raises(LoaderError, match="records no backups"):
        _loader(fat_archive, "recovery-point=0")


def test_encrypted_without_password(fat_archive: Path) -> None:
    with patch("dissect.target.loaders.tibx.TIBX") as mock_tibx_cls:
        mock_tibx_cls.open.return_value.encrypted = True
        with pytest.raises(LoaderError, match="Missing password"):
            TibxLoader(fat_archive)


def test_encrypted_with_keychain_password(fat_archive: Path) -> None:
    keychain.register_key(keychain.KeyType.PASSPHRASE, "wrong", provider="tibx")
    keychain.register_key(keychain.KeyType.PASSPHRASE, "letmein")
    try:
        with patch("dissect.target.loaders.tibx.TIBX") as mock_tibx_cls:
            mock_tibx = mock_tibx_cls.open.return_value
            mock_tibx.encrypted = True
            mock_tibx.unlock.side_effect = [InvalidPasswordError("wrong"), None]
            TibxLoader(fat_archive)
            assert mock_tibx.unlock.call_count == 2
            assert mock_tibx.unlock.call_args_list[1].args == ("letmein",)
    finally:
        keychain.KEYCHAIN.clear()


def test_not_a_tibx_raises_loader_error(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.tibx"
    bogus.write_bytes(b"\x41\x01" + b"\x00" * 0x2000)
    with pytest.raises(LoaderError, match="Failed to open TIBX archive"):
        TibxLoader(bogus)
