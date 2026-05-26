from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.cstruct import cstruct

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import Any

    from dissect.target.target import Target

cs = cstruct(endian=">")

cs.load("""
struct asl_record {
    uint64 next;
    uint64 msg_id;
    uint64 time_s;
    uint32 unknown;

    uint16 level;
    uint16 flags;

    uint32 pid;

    uint32 uid;
    uint32 gid;
    uint32 ruid;
    uint32 rgid;
    uint32 rpid;
    uint32 kvcount;

    uint64 host_ref;
    uint64 sender_ref;
    uint64 facility_ref;
    uint64 message_ref;
    uint64 ref5;
    uint64 ref6;
};
""")

ASLRecord = TargetRecordDescriptor(
    "macos/logs/asl",
    [
        ("datetime", "ts"),
        ("varint", "severity_level"),
        ("varint", "pid"),
        ("string", "asl_host"),
        ("string", "sender"),
        ("string", "facility"),
        ("string", "message"),
        ("path", "source"),
    ],
)


def _parse_asl_string_ref(data: bytes, ref: int) -> str | None:
    if ref == 0:
        return None

    if ref & 0x8000000000000000:
        ref_bytes = struct.pack(">Q", ref & 0x7FFFFFFFFFFFFFFF)
        slen = ref_bytes[0]
        return ref_bytes[1 : 1 + slen].decode("utf-8", errors="replace").rstrip("\x00")

    if ref + 6 < len(data) and data[ref : ref + 2] == b"\x00\x01":
        slen = struct.unpack(">I", data[ref + 2 : ref + 6])[0]
        if 0 < slen < 65536 and ref + 6 + slen <= len(data):
            return data[ref + 6 : ref + 6 + slen].decode("utf-8", errors="replace").rstrip("\x00")

    return None


def _valid_value(s: str | None) -> bool:
    if not s:
        return True
    printable = sum(32 <= ord(c) < 127 for c in s)
    return printable / len(s) > 0.9


def _valid_ref(data: bytes, ref: int) -> bool:
    if ref == 0:
        return False
    if ref & 0x8000000000000000:
        return True
    return ref + 6 < len(data) and data[ref : ref + 2] == b"\x00\x01"


def _parse_asl_file(data: bytes) -> Iterator[dict[str, Any]]:
    """Parse an ASL DB binary file using cstruct."""
    if len(data) < 80 or data[:6] != b"ASL DB":
        return

    now = int(datetime.now(tz=timezone.utc).timestamp())
    pos = 0x80

    while pos < len(data) - 60:
        rec_len = int.from_bytes(data[pos : pos + 2], "big")

        # Sanity checks
        if rec_len < 120 or rec_len > 65535 or pos + rec_len + 2 > len(data):
            pos += 2
            continue

        # Parse struct safely
        try:
            rec = cs.asl_record(data[pos + 2 : pos + 2 + rec_len])
        except Exception:
            pos += 2
            continue

        # Timestamp validation
        if not (946684800 < rec.time_s < now + 31536000):
            pos += 2
            continue

        refs = [
            rec.host_ref,
            rec.sender_ref,
            rec.facility_ref,
            rec.message_ref,
            rec.ref5,
            rec.ref6,
        ]

        if not any(_valid_ref(data, r) for r in refs):
            pos += 2
            continue

        # Decode strings
        host = _parse_asl_string_ref(data, rec.host_ref)
        sender = _parse_asl_string_ref(data, rec.sender_ref)
        facility = _parse_asl_string_ref(data, rec.facility_ref)
        message = _parse_asl_string_ref(data, rec.message_ref)

        if not _valid_value(host):
            host = None
        if not _valid_value(sender):
            sender = None
        if not _valid_value(facility):
            facility = None
        if not _valid_value(message):
            message = None

        if not any([host, sender, facility, message]):
            pos += 2
            continue

        yield {
            "ts": datetime.fromtimestamp(rec.time_s, tz=timezone.utc),
            "level": rec.level,
            "pid": rec.pid,
            "host": host,
            "sender": sender,
            "facility": facility,
            "message": message,
        }

        pos += rec_len + 2


class ASLPlugin(Plugin):
    """Plugin to parse macOS ASL databases."""

    ASL_PATHS = (
        "var/log/asl/*.asl",
        "var/log/powermanagement/*.asl",
        "var/log/DiagnosticMessages/*.asl",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self._asl_files = set()
        self._find_files()

    def _find_files(self) -> None:
        for pattern in self.ASL_PATHS:
            for path in self.target.fs.path("/").glob(pattern):
                if path.is_file():
                    self._asl_files.add(path)

    def check_compatible(self) -> None:
        if not self._asl_files:
            raise UnsupportedPluginError("No .asl files found")

    @export(record=ASLRecord)
    def asl(self) -> Iterator[ASLRecord]:
        """Return all apple system log messages."""
        for asl_path in self._asl_files:
            try:
                with asl_path.open("rb") as fh:
                    data = fh.read()
                records = _parse_asl_file(data)
            except Exception as e:
                self.target.log.warning("Error parsing ASL file %s: %s", asl_path, e)
                continue

            for rec in records:
                yield ASLRecord(
                    ts=rec["ts"],
                    severity_level=rec["level"],
                    pid=rec["pid"],
                    asl_host=rec["host"],
                    sender=rec["sender"],
                    facility=rec["facility"],
                    message=rec["message"],
                    source=asl_path,
                    _target=self.target,
                )
