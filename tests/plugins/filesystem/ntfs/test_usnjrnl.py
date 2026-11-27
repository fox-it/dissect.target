from __future__ import annotations

import struct
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.ntfs.usnjrnl import UsnJrnl, UsnRecord

from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.plugins.filesystem.ntfs.usnjrnl import UsnjrnlPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    import pytest

    from dissect.target.target import Target


def test_usnjrnl_normal(target_win: Target) -> None:
    """Test parsing of a usnjrnl file."""
    filesystem = NtfsFilesystem(usnjrnl=absolute_path("_data/plugins/filesystem/ntfs/usnjrnl/usnjrnl.bin").open("rb"))
    target_win.filesystems = [filesystem]

    target_win.add_plugin(UsnjrnlPlugin)

    data = list(target_win.usnjrnl())

    assert len(data) == 15214


def test_usnjrnl_timestamp_overflow_error(target_win: Target) -> None:
    """Test parsing of a usnjrnl entry whose timestamp triggers OverflowError."""
    raw = bytearray(absolute_path("_data/plugins/filesystem/ntfs/usnjrnl/usnjrnl.bin").read_bytes())
    first = next(iter(UsnJrnl(BytesIO(raw)).records()))
    ts_offset = bytes(raw).find(struct.pack("<Q", first.record.TimeStamp))
    assert ts_offset != -1
    raw[ts_offset : ts_offset + 8] = struct.pack("<Q", 0x7FFFFFFFFFFFFFFF)

    filesystem = NtfsFilesystem(usnjrnl=BytesIO(raw))
    target_win.filesystems = [filesystem]
    target_win.add_plugin(UsnjrnlPlugin)

    data = list(target_win.usnjrnl())

    assert len(data) == 15214
    assert data[0].ts is None
    assert data[1].ts is not None


def test_usnjrnl_timestamp_value_error(target_win: Target, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test parsing of a usnjrnl entry whose timestamp triggers ValueError."""
    orig_timestamp = UsnRecord.timestamp.fget
    assert orig_timestamp is not None
    calls = 0

    def raising_timestamp(self: UsnRecord) -> object:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ValueError("invalid timestamp")
        return orig_timestamp(self)

    monkeypatch.setattr(UsnRecord, "timestamp", property(raising_timestamp))

    filesystem = NtfsFilesystem(usnjrnl=absolute_path("_data/plugins/filesystem/ntfs/usnjrnl/usnjrnl.bin").open("rb"))
    target_win.filesystems = [filesystem]
    target_win.add_plugin(UsnjrnlPlugin)

    data = list(target_win.usnjrnl())

    assert len(data) == 15214
    assert data[0].ts is None
    assert data[1].ts is not None
