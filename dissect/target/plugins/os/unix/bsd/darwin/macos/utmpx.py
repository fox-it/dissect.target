from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


UTMPX_RECORD_SIZE = 628

UtmpxRecord = TargetRecordDescriptor(
    "macos/utmpx/entry",
    [
        ("datetime", "ts"),
        ("string", "user"),
        ("string", "line"),
        ("varint", "pid"),
        ("varint", "entry_type"),
        ("string", "host"),
        ("path", "source"),
    ],
)


class MacOSUtmpxPlugin(Plugin):
    """Plugin to parse macOS utmpx login records.

    Location: /private/var/run/utmpx

    Each record is 628 bytes:
        user:    256 bytes (null-terminated string)
        id:        4 bytes
        line:     32 bytes (null-terminated string)
        pid:       4 bytes (uint32 LE)
        type:      2 bytes (uint16 LE)
        padding:   2 bytes
        tv_sec:    4 bytes (uint32 LE)
        tv_usec:   4 bytes (uint32 LE)
        host:    256 bytes (null-terminated string)
        padding:  64 bytes
    """

    __namespace__ = "utmpx"

    PATHS = [
        "private/var/run/utmpx",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._utmpx_paths = []
        for p in self.PATHS:
            path = self.target.fs.path("/").joinpath(p)
            if path.exists():
                self._utmpx_paths.append(path)

    def check_compatible(self) -> None:
        if not self._utmpx_paths:
            raise UnsupportedPluginError("No utmpx file found")

    @export(record=UtmpxRecord)
    def entries(self) -> Iterator[UtmpxRecord]:
        """Parse binary utmpx login records."""
        for utmpx_path in self._utmpx_paths:
            try:
                with utmpx_path.open("rb") as fh:
                    data = fh.read()

                offset = 0
                while offset + UTMPX_RECORD_SIZE <= len(data):
                    user = (
                        struct.unpack_from("256s", data, offset)[0]
                        .split(b"\x00", 1)[0]
                        .decode("utf-8", errors="replace")
                    )
                    # id: 4 bytes at offset+256
                    line = (
                        struct.unpack_from("32s", data, offset + 260)[0]
                        .split(b"\x00", 1)[0]
                        .decode("utf-8", errors="replace")
                    )
                    pid = struct.unpack_from("<I", data, offset + 292)[0]
                    entry_type = struct.unpack_from("<H", data, offset + 296)[0]
                    # padding: 2 bytes at offset+298
                    tv_sec = struct.unpack_from("<I", data, offset + 300)[0]
                    # tv_usec at offset+304
                    host = (
                        struct.unpack_from("256s", data, offset + 308)[0]
                        .split(b"\x00", 1)[0]
                        .decode("utf-8", errors="replace")
                    )
                    # padding: 64 bytes at offset+564

                    try:
                        ts = (
                            datetime.fromtimestamp(tv_sec, tz=timezone.utc)
                            if tv_sec
                            else datetime(1970, 1, 1, tzinfo=timezone.utc)
                        )
                    except (OSError, OverflowError, ValueError):
                        ts = datetime(1970, 1, 1, tzinfo=timezone.utc)

                    yield UtmpxRecord(
                        ts=ts,
                        user=user,
                        line=line,
                        pid=pid,
                        entry_type=entry_type,
                        host=host,
                        source=utmpx_path,
                        _target=self.target,
                    )

                    offset += UTMPX_RECORD_SIZE
            except Exception as e:
                self.target.log.warning("Error parsing utmpx %s: %s", utmpx_path, e)
