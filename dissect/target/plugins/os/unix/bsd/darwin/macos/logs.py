from __future__ import annotations

import re
import struct
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


# ── Record Descriptors ───────────────────────────────────────────────────

SyslogRecord = TargetRecordDescriptor(
    "macos/logs/syslog",
    [
        ("string", "ts_raw"),
        ("string", "log_hostname"),
        ("string", "process"),
        ("string", "pid"),
        ("string", "message"),
        ("string", "log_file"),
        ("path", "source"),
    ],
)

LogFileRecord = TargetRecordDescriptor(
    "macos/logs/file",
    [
        ("string", "line"),
        ("varint", "line_number"),
        ("string", "log_file"),
        ("path", "source"),
    ],
)

LogFileListRecord = TargetRecordDescriptor(
    "macos/logs/filelist",
    [
        ("string", "log_file"),
        ("string", "log_dir"),
        ("varint", "size_bytes"),
        ("path", "source"),
    ],
)

AuditClassRecord = TargetRecordDescriptor(
    "macos/logs/audit_class",
    [
        ("string", "mask"),
        ("string", "name"),
        ("string", "description"),
        ("path", "source"),
    ],
)

AuditEventRecord = TargetRecordDescriptor(
    "macos/logs/audit_event",
    [
        ("string", "event_id"),
        ("string", "event_name"),
        ("string", "description"),
        ("string", "event_class"),
        ("path", "source"),
    ],
)

ASLRecord = TargetRecordDescriptor(
    "macos/logs/asl",
    [
        ("datetime", "ts"),
        ("varint", "level"),
        ("varint", "pid"),
        ("string", "asl_host"),
        ("string", "sender"),
        ("string", "facility"),
        ("string", "message"),
        ("string", "asl_file"),
        ("string", "asl_dir"),
        ("path", "source"),
    ],
)


def _parse_asl_string_ref(data, ref):
    """Decode an ASL string reference (inline or external)."""
    if ref == 0:
        return ""
    if ref & 0x8000000000000000:
        # Inline: high bit set, first byte of remaining 7 = length
        ref_bytes = struct.pack(">Q", ref & 0x7FFFFFFFFFFFFFFF)
        slen = ref_bytes[0]
        return ref_bytes[1 : 1 + slen].decode("utf-8", errors="replace").rstrip("\x00")
    # External: offset into file, format is \x00\x01 + uint32(length) + string
    if ref + 6 < len(data) and data[ref : ref + 2] == b"\x00\x01":
        slen = struct.unpack(">I", data[ref + 2 : ref + 6])[0]
        if 0 < slen < 65536 and ref + 6 + slen <= len(data):
            return data[ref + 6 : ref + 6 + slen].decode("utf-8", errors="replace")
    return ""


def _parse_asl_file(data):
    """Parse an ASL DB binary file and yield record dicts."""
    if len(data) < 80 or data[:6] != b"ASL DB":
        return

    pos = 0x80  # skip header area
    while pos < len(data) - 60:
        rec_len = struct.unpack(">H", data[pos : pos + 2])[0]
        if rec_len < 100 or rec_len > 65535 or pos + rec_len + 2 > len(data):
            pos += 2
            continue

        # Check timestamp at expected offset (+18 from record start)
        time_s = struct.unpack(">Q", data[pos + 18 : pos + 26])[0]
        if not (1000000000 < time_s < 2000000000):
            pos += 2
            continue

        # Parse record fields
        p = pos + 2
        p += 8  # next offset
        p += 8  # msg_id
        p += 8  # time_s (already read)
        struct.unpack(">I", data[p : p + 4])[0]
        p += 4
        level = struct.unpack(">H", data[p : p + 2])[0]
        p += 2
        p += 2  # flags
        pid = struct.unpack(">I", data[p : p + 4])[0]
        p += 4
        p += 4  # uid
        p += 4  # gid
        p += 4  # ruid
        p += 4  # rgid
        p += 4  # rpid
        p += 4  # kvcount

        # 6 string references
        refs = []
        for _ in range(6):
            ref = struct.unpack(">Q", data[p : p + 8])[0]
            refs.append(ref)
            p += 8

        host = _parse_asl_string_ref(data, refs[0])
        sender = _parse_asl_string_ref(data, refs[1])
        facility = _parse_asl_string_ref(data, refs[2])
        message = _parse_asl_string_ref(data, refs[3])

        try:
            ts = datetime.fromtimestamp(time_s, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            ts = datetime(1970, 1, 1, tzinfo=timezone.utc)

        yield {
            "ts": ts,
            "level": level,
            "pid": pid,
            "host": host,
            "sender": sender,
            "facility": facility,
            "message": message,
        }

        pos += rec_len + 2


# Syslog line pattern: "Mon DD HH:MM:SS hostname process[pid]: message"
SYSLOG_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(\S+)\s+"  # hostname
    r"([^\[:\s]+)"  # process name
    r"(?:\[(\d+)\])?"  # optional [pid]
    r":\s*(.*)"  # message
)


class MacOSLogsPlugin(Plugin):
    """Plugin to parse macOS log files, ASL databases, and audit configuration.

    Collects logs from:
    - /var/log/ and /private/var/log/ (system logs, ASL databases)
    - ~/Library/Logs/ (per-user application logs)
    - /etc/security/ (audit configuration)
    """

    __namespace__ = "logs"

    ASL_GLOBS = [
        "var/log/asl/*.asl",
        "private/var/log/asl/*.asl",
        "var/log/powermanagement/*.asl",
        "private/var/log/powermanagement/*.asl",
        "private/var/log/DiagnosticMessages/*.asl",
        "var/log/DiagnosticMessages/*.asl",
    ]

    LOG_GLOBS = [
        "var/log/**/*.log",
        "var/log/**/*.log.*",
        "var/log/system.log",
        "var/log/system.log.*",
        "private/var/log/**/*.log",
        "private/var/log/**/*.log.*",
        "private/var/log/system.log",
        "private/var/log/system.log.*",
        "Users/*/Library/Logs/**/*.log",
        "Users/*/Library/Logs/**/*.log.*",
    ]

    SYSLOG_FILES = [
        "var/log/system.log",
        "private/var/log/system.log",
    ]

    INSTALL_LOG_FILES = [
        "var/log/install.log",
        "private/var/log/install.log",
    ]

    AUDIT_DIR = "etc/security"

    def __init__(self, target):
        super().__init__(target)
        self._log_files = set()
        for pattern in self.LOG_GLOBS:
            for path in self.target.fs.path("/").glob(pattern):
                if path.is_file():
                    self._log_files.add(path)
        self._log_files = sorted(self._log_files)

        self._asl_files = set()
        for pattern in self.ASL_GLOBS:
            for path in self.target.fs.path("/").glob(pattern):
                if path.is_file():
                    self._asl_files.add(path)
        self._asl_files = sorted(self._asl_files)

    def check_compatible(self) -> None:
        audit_path = self.target.fs.path(f"/{self.AUDIT_DIR}")
        if not self._log_files and not audit_path.exists():
            raise UnsupportedPluginError("No log files or audit config found")

    def _read_text_lines(self, path):
        """Read a text file and yield lines, handling encoding errors."""
        try:
            with path.open("rb") as fh:
                data = fh.read()
            text = data.decode("utf-8", errors="replace")
            return text.splitlines()
        except Exception:
            return []

    def _parse_syslog_line(self, line):
        """Parse a syslog-format line into components."""
        m = SYSLOG_RE.match(line)
        if m:
            return m.group(1), m.group(2), m.group(3), m.group(4) or "", m.group(5)
        return None

    # ── List all log files ───────────────────────────────────────────────

    @export(record=LogFileListRecord)
    def list(self) -> Iterator[LogFileListRecord]:
        """List all discovered log files with their sizes."""
        for log_path in self._log_files:
            try:
                stat = log_path.stat()
                size = stat.st_size if hasattr(stat, "st_size") else 0
            except Exception:
                size = 0

            yield LogFileListRecord(
                log_file=log_path.name,
                log_dir=str(log_path.parent),
                size_bytes=size,
                source=log_path,
                _target=self.target,
            )

    # ── System log (syslog format) ───────────────────────────────────────

    @export(record=SyslogRecord)
    def system(self) -> Iterator[SyslogRecord]:
        """Parse system.log entries in syslog format."""
        for rel_path in self.SYSLOG_FILES:
            path = self.target.fs.path(f"/{rel_path}")
            if not path.exists():
                continue
            try:
                yield from self._parse_syslog_file(path)
            except Exception as e:
                self.target.log.warning("Error parsing %s: %s", path, e)

    def _parse_syslog_file(self, path):
        lines = self._read_text_lines(path)
        for line in lines:
            parsed = self._parse_syslog_line(line)
            if parsed:
                ts_raw, log_hostname, process, pid, message = parsed
                yield SyslogRecord(
                    ts_raw=ts_raw,
                    log_hostname=log_hostname,
                    process=process,
                    pid=pid,
                    message=message,
                    log_file=path.name,
                    source=path,
                    _target=self.target,
                )

    # ── Install log ──────────────────────────────────────────────────────

    @export(record=SyslogRecord)
    def install(self) -> Iterator[SyslogRecord]:
        """Parse install.log entries (software installation history)."""
        for rel_path in self.INSTALL_LOG_FILES:
            path = self.target.fs.path(f"/{rel_path}")
            if not path.exists():
                continue
            try:
                yield from self._parse_syslog_file(path)
            except Exception as e:
                self.target.log.warning("Error parsing %s: %s", path, e)

    # ── User logs ────────────────────────────────────────────────────────

    @export(record=LogFileRecord)
    def user(self) -> Iterator[LogFileRecord]:
        """Parse user application log files from ~/Library/Logs/."""
        for log_path in self._log_files:
            if "/Library/Logs/" not in str(log_path):
                continue
            try:
                lines = self._read_text_lines(log_path)
                for i, line in enumerate(lines, 1):
                    if not line.strip():
                        continue
                    yield LogFileRecord(
                        line=line,
                        line_number=i,
                        log_file=log_path.name,
                        source=log_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s: %s", log_path, e)

    # ── All raw log lines ────────────────────────────────────────────────

    @export(record=LogFileRecord)
    def all_raw(self) -> Iterator[LogFileRecord]:
        """Parse all log files as raw lines."""
        for log_path in self._log_files:
            try:
                lines = self._read_text_lines(log_path)
                for i, line in enumerate(lines, 1):
                    if not line.strip():
                        continue
                    yield LogFileRecord(
                        line=line,
                        line_number=i,
                        log_file=log_path.name,
                        source=log_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s: %s", log_path, e)

    # ── ASL databases ────────────────────────────────────────────────────

    def _parse_asl_path(self, asl_path):
        """Read an ASL file from the target filesystem and parse it."""
        with asl_path.open("rb") as fh:
            data = fh.read()
        return _parse_asl_file(data)

    @export(record=ASLRecord)
    def asl(self) -> Iterator[ASLRecord]:
        """Parse all ASL (Apple System Log) binary database files."""
        for asl_path in self._asl_files:
            try:
                for rec in self._parse_asl_path(asl_path):
                    yield ASLRecord(
                        ts=rec["ts"],
                        level=rec["level"],
                        pid=rec["pid"],
                        asl_host=rec["host"],
                        sender=rec["sender"],
                        facility=rec["facility"],
                        message=rec["message"],
                        asl_file=asl_path.name,
                        asl_dir=str(asl_path.parent),
                        source=asl_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing ASL file %s: %s", asl_path, e)

    @export(record=ASLRecord)
    def asl_system(self) -> Iterator[ASLRecord]:
        """Parse ASL files from /var/log/asl/ (system-wide ASL logs)."""
        for asl_path in self._asl_files:
            if "/asl/" not in str(asl_path):
                continue
            try:
                for rec in self._parse_asl_path(asl_path):
                    yield ASLRecord(
                        ts=rec["ts"],
                        level=rec["level"],
                        pid=rec["pid"],
                        asl_host=rec["host"],
                        sender=rec["sender"],
                        facility=rec["facility"],
                        message=rec["message"],
                        asl_file=asl_path.name,
                        asl_dir=str(asl_path.parent),
                        source=asl_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing ASL file %s: %s", asl_path, e)

    @export(record=ASLRecord)
    def asl_powermanagement(self) -> Iterator[ASLRecord]:
        """Parse ASL files from /var/log/powermanagement/ (sleep/wake events)."""
        for asl_path in self._asl_files:
            if "/powermanagement/" not in str(asl_path):
                continue
            try:
                for rec in self._parse_asl_path(asl_path):
                    yield ASLRecord(
                        ts=rec["ts"],
                        level=rec["level"],
                        pid=rec["pid"],
                        asl_host=rec["host"],
                        sender=rec["sender"],
                        facility=rec["facility"],
                        message=rec["message"],
                        asl_file=asl_path.name,
                        asl_dir=str(asl_path.parent),
                        source=asl_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing ASL file %s: %s", asl_path, e)

    @export(record=ASLRecord)
    def asl_diagnostics(self) -> Iterator[ASLRecord]:
        """Parse ASL files from /private/var/log/DiagnosticMessages/."""
        for asl_path in self._asl_files:
            if "/DiagnosticMessages/" not in str(asl_path):
                continue
            try:
                for rec in self._parse_asl_path(asl_path):
                    yield ASLRecord(
                        ts=rec["ts"],
                        level=rec["level"],
                        pid=rec["pid"],
                        asl_host=rec["host"],
                        sender=rec["sender"],
                        facility=rec["facility"],
                        message=rec["message"],
                        asl_file=asl_path.name,
                        asl_dir=str(asl_path.parent),
                        source=asl_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing ASL file %s: %s", asl_path, e)

    # ── Audit classes (/etc/security/audit_class) ────────────────────────

    @export(record=AuditClassRecord)
    def audit_classes(self) -> Iterator[AuditClassRecord]:
        """Parse audit class definitions from /etc/security/audit_class."""
        path = self.target.fs.path("/etc/security/audit_class")
        if not path.exists():
            return

        lines = self._read_text_lines(path)
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 3:
                yield AuditClassRecord(
                    mask=parts[0],
                    name=parts[1],
                    description=parts[2],
                    source=path,
                    _target=self.target,
                )

    # ── Audit events (/etc/security/audit_event) ─────────────────────────

    @export(record=AuditEventRecord)
    def audit_events(self) -> Iterator[AuditEventRecord]:
        """Parse audit event definitions from /etc/security/audit_event."""
        path = self.target.fs.path("/etc/security/audit_event")
        if not path.exists():
            return

        lines = self._read_text_lines(path)
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 4:
                yield AuditEventRecord(
                    event_id=parts[0],
                    event_name=parts[1],
                    description=parts[2],
                    event_class=parts[3],
                    source=path,
                    _target=self.target,
                )
