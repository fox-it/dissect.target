from __future__ import annotations

import gzip
import io
from typing import TYPE_CHECKING

import pytest

from dissect.target.containers.fortifw import FortiFirmwareFile, find_xor_key, main

if TYPE_CHECKING:
    from pathlib import Path

# decompressed header of FGT_VM64-v7.4.3.F-build2573-FORTINET.out
FIRMWARE_HEADER = bytes.fromhex(
    """
9ede e4a5 f69f c9aa 92de 92ff b7eb 060a
6475 5c76 7173 6a68 4347 4a4c 774c 7dac
b893 c5e0 81d7 aef0 f58b f3ae d3bf d581
a9f1 a2fb a2fc b0eb 9eca 93c6 83d1 b5fa
9bdb e1a0 f39a d8bb 83cf 83ee a1fd a6c1
e9b1 e2bb e2bc f0ab de8a d386 c391 f5ba
db9b a1e0 b3da 98fb c38f c3ae e1bd e681
a9f1 a2fb a2fc b0eb 9eca 93c6 83d1 b5fa
"""
)


def test_find_xor_key() -> None:
    fh = io.BytesIO(FIRMWARE_HEADER)
    for offset in (0x30, 0x40, 0x31, 0x35):
        fh.seek(offset)
        key = find_xor_key(fh)
        assert key.isalnum()
        assert key == b"aA8BWlDd0EFfCQUh8IAJMKZLmMCNYOzP"

    # incorrect key as at offset 0 it does not decode to zero bytes
    fh.seek(0)
    key = find_xor_key(fh)
    assert not key.isalnum()


@pytest.mark.parametrize(
    ("header", "is_gzipped"),
    [
        pytest.param(FIRMWARE_HEADER, False, id="uncompressed"),
        pytest.param(gzip.compress(FIRMWARE_HEADER), True, id="compressed"),
    ],
)
def test_deobfuscate_firmware_file(header: bytes, is_gzipped: bool) -> None:
    ff = FortiFirmwareFile(io.BytesIO(header))

    # magic bytes
    ff.seek(12)
    assert ff.read(4) == b"\xff\x00\xaa\x55"

    # firmware name
    ff.seek(16)
    assert ff.read(32) == b"FGVM64-7.04-FW-build2573-240201-"

    # test metadata
    assert ff.is_gzipped == is_gzipped
    assert ff.size == len(FIRMWARE_HEADER)


def test_gzip_trailer() -> None:
    trailer_data = b"TRAILER DATA"

    gzip_data = gzip.compress(FIRMWARE_HEADER)
    fh = io.BytesIO(gzip_data + trailer_data)
    ff = FortiFirmwareFile(fh)

    assert ff.is_gzipped
    assert ff.size == len(FIRMWARE_HEADER)
    assert ff.trailer_offset == len(gzip_data)
    assert ff.trailer_data == trailer_data


def test_fortifw_main(tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]) -> None:
    fw_path = tmp_path / "fw.bin"
    fw_path.write_bytes(FIRMWARE_HEADER)

    main([str(fw_path)])
    stdout, _ = capsysbinary.readouterr()
    assert b"\xff\x00\xaa\x55FGVM64-7.04-FW-build2573-240201-" in stdout
