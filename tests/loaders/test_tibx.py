from __future__ import annotations

import struct
import sys
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.exceptions import LoaderError
from dissect.target.helpers import keychain
from dissect.target.loaders.tibx import TibxLoader
from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

PAGE = 0x1000


def _crc32c(data: bytes) -> int:
    from dissect.archive.tibx.crc32c import page_crc32c

    return page_crc32c(data)


def _finalize(pg: bytearray) -> bytes:
    pg[4:8] = struct.pack(">I", _crc32c(bytes(pg)))
    return bytes(pg)


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


def _build_tibx_archive(volume_data: bytes) -> bytes:
    """Build a minimal synthetic TIBX archive wrapping ``volume_data`` as one volume.

    Constructs a two-page archive: one ARCH header with inline data_map/segment_map
    LSM mem-trees, and one zstd-compressed SG data segment.
    """
    if sys.version_info >= (3, 14):
        from compression import zstd  # novermin
    else:
        from backports import zstd

    blob = zstd.compress(volume_data)

    # SG data segment page
    sg = bytearray(PAGE)
    sg[0], sg[1] = 0x41, 0xFF
    sg[8:12] = b"SG\x00\x01"
    struct.pack_into(">III", sg, 0x0C, len(volume_data), len(blob), 0)
    struct.pack_into(">HH", sg, 0x18, 0x0300, 0)  # zstd compression
    sg[0x2C : 0x2C + len(blob)] = blob

    # data_map key: volume_id(8) + source_offset(8) + length(3) + slice_id(4) + extent_id(8) = 31 bytes
    dm_key = struct.pack(">QQ", 10, 0) + len(volume_data).to_bytes(3, "big") + struct.pack(">IQ", 2, 1)
    dm_val = struct.pack(">QH", 100, 0xFFFF)  # segment_id=100, whole-segment sentinel

    # segment_map key: segment_id(8); value: page_count(4 LE) + page_offset(4 BE) + slice_id(4 BE) + hash(20)
    sm_key = struct.pack(">Q", 100)
    sm_val = struct.pack("<I", 1) + struct.pack(">II", 1, 2) + b"\x00" * 20

    # Compact cell stream for one cell (group of 1, alive bitmap = 0x01)
    def compact_one(key: bytes, val: bytes) -> bytes:
        return struct.pack("<I", 1 | (0x01 << 24)) + key + val

    dm_stream = compact_one(dm_key, dm_val)
    sm_stream = compact_one(sm_key, sm_val)

    # L-SB records (mem-tree with one cell each)
    def lsb_record(key_len: int, val_len: int, stream: bytes) -> bytes:
        record = bytearray(0x178)
        record[0:4] = b"L-SB"
        record[4] = 1  # format version
        record[5] = 0  # ctree_count - 2
        record[6] = 8  # ctree_max - 2
        struct.pack_into(">IIII", record, 8, 1, 0, key_len, val_len)
        record[0x158] = 0  # encoding: raw
        struct.pack_into(">H", record, 0x15A, 1)  # node_count
        struct.pack_into(">II", record, 0x15C, len(stream), 0)
        return bytes(record) + stream

    dm_sb = lsb_record(31, 10, dm_stream)
    sm_sb = lsb_record(8, 32, sm_stream)

    # TLV directory: 19 slots; slots 1 (data_map) and 2 (segment_map) carry the L-SBs
    tlv = bytearray()
    for index in range(19):
        payload = {1: dm_sb, 2: sm_sb}.get(index, b"")
        tlv += struct.pack(">I", len(payload))
        tlv += payload
        stride = (len(payload) + 7) & ~3
        tlv += b"\x00" * (stride - 4 - len(payload))

    # ARCH header page
    header_size = 0x400 + len(tlv)
    pg = bytearray(PAGE)
    pg[0], pg[1] = 0x41, 0x01
    pg[8:12] = b"ARCH"
    struct.pack_into(">I", pg, 0x0C, header_size)
    struct.pack_into(">H", pg, 0x10, 8)
    pg[0x18:0x20] = (1000).to_bytes(8, "big")
    pg[0x20:0x28] = (2000).to_bytes(8, "big")
    pg[0x28:0x38] = b"\xab" * 16
    struct.pack_into(">Q", pg, 8 + 0x188, 1)  # commit sequence
    pg[8 + 0x400 : 8 + 0x400 + len(tlv)] = tlv

    return _finalize(pg) + _finalize(sg)


FILE_CONTENT = b"hello from inside a tibx backup"


@pytest.fixture
def fat_archive(tmp_path: Path) -> Path:
    image = _build_fat12_image(FILE_CONTENT)
    path = tmp_path / "backup.tibx"
    path.write_bytes(_build_tibx_archive(image))
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


@pytest.mark.usefixtures("_registered_loader")
def test_target_open_selects_loader(fat_archive: Path) -> None:
    target = Target.open(fat_archive)
    assert isinstance(target._loader, TibxLoader)
    assert len(target.filesystems) == 1


def test_encrypted_without_password(fat_archive: Path) -> None:
    with patch("dissect.target.loaders.tibx.TIBX") as mock_tibx_cls:
        mock_tibx_cls.open.return_value.encrypted = True
        with pytest.raises(LoaderError, match="Missing password"):
            TibxLoader(fat_archive)


def test_encrypted_with_keychain_password(fat_archive: Path) -> None:
    from dissect.archive.tibx.exceptions import InvalidPasswordError

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
