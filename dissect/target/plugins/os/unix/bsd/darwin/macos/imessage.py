from __future__ import annotations

import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


# iMessage timestamps: nanoseconds since 2001-01-01 (Cocoa epoch)
COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _cocoa_ns_ts(value):
    """Convert Cocoa nanosecond timestamp to datetime."""
    if value:
        try:
            return COCOA_EPOCH + timedelta(seconds=value / 1_000_000_000)
        except (OSError, OverflowError, ValueError):
            return COCOA_EPOCH
    return COCOA_EPOCH


MessageRecord = TargetRecordDescriptor(
    "macos/imessage/messages",
    [
        ("datetime", "ts"),
        ("string", "text"),
        ("boolean", "is_from_me"),
        ("boolean", "is_read"),
        ("string", "service"),
        ("string", "handle_id"),
        ("string", "associated_message_guid"),
        ("string", "balloon_bundle_id"),
        ("boolean", "cache_has_attachments"),
        ("path", "source"),
    ],
)

ChatRecord = TargetRecordDescriptor(
    "macos/imessage/chats",
    [
        ("string", "chat_identifier"),
        ("string", "service_name"),
        ("string", "display_name"),
        ("string", "room_name"),
        ("boolean", "is_archived"),
        ("path", "source"),
    ],
)

AttachmentRecord = TargetRecordDescriptor(
    "macos/imessage/attachments",
    [
        ("datetime", "ts_created"),
        ("string", "filename"),
        ("string", "mime_type"),
        ("string", "uti"),
        ("varint", "transfer_state"),
        ("boolean", "is_outgoing"),
        ("varint", "total_bytes"),
        ("path", "source"),
    ],
)


class IMessagePlugin(Plugin):
    """Plugin to parse macOS iMessage chat.db.

    Parses messages, chats, and attachments from the iMessage database.

    Location: ~/Library/Messages/chat.db
    """

    __namespace__ = "imessage"

    DB_GLOB = "Users/*/Library/Messages/chat.db"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.DB_GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No iMessage chat.db found")

    def _open_db(self, db_path):
        with db_path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        # Copy WAL and SHM if they exist
        for suffix in ["-wal", "-shm"]:
            src = db_path.parent.joinpath(db_path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    # ── Messages ────────────────────────────────────────────────────────

    @export(record=MessageRecord)
    def messages(self) -> Iterator[MessageRecord]:
        """Parse iMessage/SMS messages with sender handle information."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_messages(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing iMessages at %s: %s", db_path, e)

    def _parse_messages(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    m.date,
                    m.text,
                    m.is_from_me,
                    m.is_read,
                    m.service,
                    h.id AS handle_id,
                    m.associated_message_guid,
                    m.balloon_bundle_id,
                    m.cache_has_attachments
                FROM message m
                LEFT JOIN handle h ON m.handle_id = h.ROWID
                ORDER BY m.date DESC
            """)
            for row in cursor:
                yield MessageRecord(
                    ts=_cocoa_ns_ts(row["date"]),
                    text=row["text"] or "",
                    is_from_me=bool(row["is_from_me"]),
                    is_read=bool(row["is_read"]),
                    service=row["service"] or "",
                    handle_id=row["handle_id"] or "",
                    associated_message_guid=row["associated_message_guid"] or "",
                    balloon_bundle_id=row["balloon_bundle_id"] or "",
                    cache_has_attachments=bool(row["cache_has_attachments"]),
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    # ── Chats ───────────────────────────────────────────────────────────

    @export(record=ChatRecord)
    def chats(self) -> Iterator[ChatRecord]:
        """Parse iMessage/SMS chat entries."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_chats(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing iMessage chats at %s: %s", db_path, e)

    def _parse_chats(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT chat_identifier, service_name, display_name,
                       room_name, is_archived
                FROM chat
            """)
            for row in cursor:
                yield ChatRecord(
                    chat_identifier=row["chat_identifier"] or "",
                    service_name=row["service_name"] or "",
                    display_name=row["display_name"] or "",
                    room_name=row["room_name"] or "",
                    is_archived=bool(row["is_archived"]),
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    # ── Attachments ─────────────────────────────────────────────────────

    @export(record=AttachmentRecord)
    def attachments(self) -> Iterator[AttachmentRecord]:
        """Parse iMessage/SMS attachments."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_attachments(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing iMessage attachments at %s: %s", db_path, e)

    def _parse_attachments(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT created_date, filename, mime_type, uti,
                       transfer_state, is_outgoing, total_bytes
                FROM attachment
                ORDER BY created_date DESC
            """)
            for row in cursor:
                yield AttachmentRecord(
                    ts_created=_cocoa_ns_ts(row["created_date"]),
                    filename=row["filename"] or "",
                    mime_type=row["mime_type"] or "",
                    uti=row["uti"] or "",
                    transfer_state=row["transfer_state"] or 0,
                    is_outgoing=bool(row["is_outgoing"]),
                    total_bytes=row["total_bytes"] or 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()
