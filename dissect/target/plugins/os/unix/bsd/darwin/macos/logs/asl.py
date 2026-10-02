from __future__ import annotations

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

cs.load("""
struct asl_string_header {
    uint16 marker;
    uint32 length;
};
""")


ASLRecord = TargetRecordDescriptor(
    "macos/logs/asl",
    [
        ("datetime", "ts"),
        ("string", "priority_level"),
        ("varint", "pid"),
        ("string", "asl_host"),
        ("string", "sender"),
        ("string", "facility"),
        ("string", "message"),
        ("path", "source"),
    ],
)


def _parse_asl_string_ref(data: bytes, ref: int) -> str | None:
    # Resolve a string reference from the ASL file (inline or external)
    if ref == 0:
        return None

    # Inline string packed into the reference itself
    if ref & 0x8000000000000000:
        ref_bytes = (ref & 0x7FFFFFFFFFFFFFFF).to_bytes(8, "big")
        slen = ref_bytes[0]
        return ref_bytes[1 : 1 + slen].decode("utf-8", errors="replace").rstrip("\x00")

    # External string stored elsewhere in the file
    if ref + 6 < len(data) and data[ref : ref + 2] == b"\x00\x01":
        try:
            hdr = cs.asl_string_header(data[ref : ref + 6])
            slen = hdr.length
        except Exception:
            return None

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
    # Basic file validation (header + minimum size)
    if len(data) < 80 or data[:6] != b"ASL DB":
        return

    now = int(datetime.now(tz=timezone.utc).timestamp())
    pos = 0x80  # Records typically start after header

    # Iterate through file and try to locate valid ASL records
    while pos < len(data) - 60:
        rec_len = int.from_bytes(data[pos : pos + 2], "big")

        # Skip invalid or unrealistic record sizes
        if rec_len < 120 or rec_len > 65535 or pos + rec_len + 2 > len(data):
            pos += 2
            continue

        try:
            # Parse record structure using cstruct
            rec = cs.asl_record(data[pos + 2 : pos + 2 + rec_len])
        except Exception:
            pos += 2
            continue

        # Filter out invalid timestamps
        if not (946684800 < rec.time_s < now + 31536000):
            pos += 2
            continue

        # Validate that at least one string reference looks valid
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

        # Decode referenced strings (host, sender, etc.)
        host = _parse_asl_string_ref(data, rec.host_ref)
        sender = _parse_asl_string_ref(data, rec.sender_ref)
        facility = _parse_asl_string_ref(data, rec.facility_ref)
        message = _parse_asl_string_ref(data, rec.message_ref)

        # Drop non-printable strings
        if not _valid_value(host):
            host = None
        if not _valid_value(sender):
            sender = None
        if not _valid_value(facility):
            facility = None
        if not _valid_value(message):
            message = None

        # Skip records without meaningful string content
        if not any([host, sender, facility, message]):
            pos += 2
            continue

        # Yield parsed log entry
        yield {
            "ts": datetime.fromtimestamp(rec.time_s, tz=timezone.utc),
            "level": rec.level,
            "pid": rec.pid,
            "host": host,
            "sender": sender,
            "facility": facility,
            "message": message,
        }

        # Move to next record
        pos += rec_len + 2


PRIORITY_LEVEL_MAP = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notice",
    6: "Informational",
    7: "Debug",
}


class ASLPlugin(Plugin):
    """Plugin to parse macOS Apple System Log (ASL) databases.

    The Apple System Log (ASL) system is a macOS logging mechanism designed with a similar goal
    to the traditional Unix syslog API. ASL logs are stored in a proprietary binary format and
    are typically located in /private/var/log/asl/.

    References:
        - https://asl.readthedocs.io/en/latest/api.html#asl-messages
        - https://www.cyberengage.org/post/making-sense-of-macos-logs-part1-a-user-friendly-guide
    """

    ASL_PATHS = (
        "var/log/asl/*.asl",
        "var/log/powermanagement/*.asl",
        "var/log/DiagnosticMessages/*.asl",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self._asl_files = self._find_files()

    def _find_files(self) -> set:
        files = set()

        for pattern in self.ASL_PATHS:
            for path in self.target.fs.path("/").glob(pattern):
                if path.is_file():
                    files.add(path)

        return files

    def check_compatible(self) -> None:
        if not self._asl_files:
            raise UnsupportedPluginError("No .asl files found")

    @export(record=ASLRecord)
    def asl(self) -> Iterator[ASLRecord]:
        """Return all macOS Apple System Log (ASL) messages.

        Yields ASLRecord with the following fields:

        .. code-block:: text

            ts (datetime): Timestamp (UTC).
            priority_level (string): ASL priority level.
            pid (varint): Process ID.
            asl_host (string): Hostname as stored in the ASL record.
            sender (string): Sender process name.
            facility (string): Logging facility.
            message (string): Log message content.
            source (path): Path to the ASL file.
        """
        for asl_path in self._asl_files:
            try:
                with asl_path.open("rb") as fh:
                    data = fh.read()
                records = _parse_asl_file(data)
            except Exception as e:
                self.target.log.warning("Error parsing ASL file %s: %s", asl_path, e)
                continue

            for rec in records:
                level = rec["level"]
                priority_level = PRIORITY_LEVEL_MAP.get(level, level)

                yield ASLRecord(
                    ts=rec["ts"],
                    priority_level=priority_level,
                    pid=rec["pid"],
                    asl_host=rec["host"],
                    sender=rec["sender"],
                    facility=rec["facility"],
                    message=rec["message"],
                    source=asl_path,
                    _target=self.target,
                )
