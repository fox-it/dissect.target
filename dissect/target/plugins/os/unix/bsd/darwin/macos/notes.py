from __future__ import annotations

import gzip
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _cocoa_ts(value):
    if value:
        try:
            return COCOA_EPOCH + timedelta(seconds=value)
        except (OSError, OverflowError, ValueError):
            return COCOA_EPOCH
    return COCOA_EPOCH


def _extract_note_text(data):
    """Extract readable text from note body (gzipped protobuf)."""
    if not data:
        return ""
    try:
        decompressed = gzip.decompress(data)
    except Exception:
        decompressed = data
    # Extract printable characters from protobuf binary
    text = "".join(chr(b) if 32 <= b < 127 or b in (10, 13) else " " for b in decompressed)
    return " ".join(text.split())


NoteRecord = TargetRecordDescriptor(
    "macos/notes/note",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_modified"),
        ("string", "title"),
        ("string", "snippet"),
        ("string", "body"),
        ("string", "folder"),
        ("string", "account"),
        ("boolean", "is_pinned"),
        ("boolean", "is_deleted"),
        ("boolean", "is_password_protected"),
        ("varint", "note_id"),
        ("path", "source"),
    ],
)

NoteFolderRecord = TargetRecordDescriptor(
    "macos/notes/folder",
    [
        ("string", "folder_name"),
        ("varint", "folder_type"),
        ("boolean", "is_deleted"),
        ("varint", "folder_id"),
        ("path", "source"),
    ],
)

NoteAccountRecord = TargetRecordDescriptor(
    "macos/notes/account",
    [
        ("string", "account_name"),
        ("varint", "account_type"),
        ("string", "identifier"),
        ("varint", "account_id"),
        ("path", "source"),
    ],
)

NoteAttachmentRecord = TargetRecordDescriptor(
    "macos/notes/attachment",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_modified"),
        ("string", "filename"),
        ("string", "mime_type"),
        ("string", "title"),
        ("varint", "file_size"),
        ("varint", "note_id"),
        ("string", "identifier"),
        ("path", "source"),
    ],
)


class AppleNotesPlugin(Plugin):
    """Plugin to parse Apple Notes from NoteStore.sqlite.

    Parses notes, folders, accounts, and attachments from the macOS
    Notes application database.

    Location: ~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite
    """

    __namespace__ = "notes"

    DB_GLOB = "Users/*/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.DB_GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No NoteStore.sqlite found")

    def _open_db(self, db_path):
        with db_path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        for suffix in ["-wal", "-shm"]:
            src = db_path.parent.joinpath(db_path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    # ── Notes ────────────────────────────────────────────────────────────

    @export(record=NoteRecord)
    def entries(self) -> Iterator[NoteRecord]:
        """Parse all notes with title, snippet, body text, folder, and timestamps."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_notes(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing notes at %s: %s", db_path, e)

    def _parse_notes(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    n.Z_PK,
                    n.ZTITLE1,
                    n.ZSNIPPET,
                    n.ZCREATIONDATE3,
                    n.ZMODIFICATIONDATE1,
                    n.ZFOLDER,
                    n.ZMARKEDFORDELETION,
                    n.ZISPINNED,
                    n.ZISPASSWORDPROTECTED,
                    f.ZTITLE2 AS folder_name,
                    a.ZNAME AS account_name,
                    nd.ZDATA
                FROM ZICCLOUDSYNCINGOBJECT n
                LEFT JOIN ZICCLOUDSYNCINGOBJECT f ON n.ZFOLDER = f.Z_PK
                LEFT JOIN ZICCLOUDSYNCINGOBJECT a ON n.ZACCOUNT7 = a.Z_PK
                LEFT JOIN ZICNOTEDATA nd ON nd.ZNOTE = n.Z_PK
                WHERE n.Z_ENT = (
                    SELECT Z_ENT FROM Z_PRIMARYKEY WHERE Z_NAME = 'ICNote'
                )
                AND n.ZTITLE1 IS NOT NULL
                ORDER BY n.ZMODIFICATIONDATE1 DESC
            """)
            for row in cursor:
                body = _extract_note_text(row["ZDATA"]) if row["ZDATA"] else ""

                yield NoteRecord(
                    ts_created=_cocoa_ts(row["ZCREATIONDATE3"]),
                    ts_modified=_cocoa_ts(row["ZMODIFICATIONDATE1"]),
                    title=row["ZTITLE1"] or "",
                    snippet=row["ZSNIPPET"] or "",
                    body=body,
                    folder=row["folder_name"] or "",
                    account=row["account_name"] or "",
                    is_pinned=bool(row["ZISPINNED"]),
                    is_deleted=bool(row["ZMARKEDFORDELETION"]),
                    is_password_protected=bool(row["ZISPASSWORDPROTECTED"]),
                    note_id=row["Z_PK"] or 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    # ── Folders ──────────────────────────────────────────────────────────

    @export(record=NoteFolderRecord)
    def folders(self) -> Iterator[NoteFolderRecord]:
        """Parse note folders."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_folders(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing note folders at %s: %s", db_path, e)

    def _parse_folders(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT Z_PK, ZTITLE2, ZFOLDERTYPE, ZMARKEDFORDELETION
                FROM ZICCLOUDSYNCINGOBJECT
                WHERE Z_ENT = (
                    SELECT Z_ENT FROM Z_PRIMARYKEY WHERE Z_NAME = 'ICFolder'
                )
            """)
            for row in cursor:
                yield NoteFolderRecord(
                    folder_name=row["ZTITLE2"] or "",
                    folder_type=row["ZFOLDERTYPE"] or 0,
                    is_deleted=bool(row["ZMARKEDFORDELETION"]),
                    folder_id=row["Z_PK"] or 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    # ── Accounts ─────────────────────────────────────────────────────────

    @export(record=NoteAccountRecord)
    def accounts(self) -> Iterator[NoteAccountRecord]:
        """Parse note accounts (iCloud, local, etc.)."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_accounts(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing note accounts at %s: %s", db_path, e)

    def _parse_accounts(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT Z_PK, ZNAME, ZACCOUNTTYPE, ZIDENTIFIER
                FROM ZICCLOUDSYNCINGOBJECT
                WHERE Z_ENT = (
                    SELECT Z_ENT FROM Z_PRIMARYKEY WHERE Z_NAME = 'ICAccount'
                )
            """)
            for row in cursor:
                yield NoteAccountRecord(
                    account_name=row["ZNAME"] or "",
                    account_type=row["ZACCOUNTTYPE"] or 0,
                    identifier=row["ZIDENTIFIER"] or "",
                    account_id=row["Z_PK"] or 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    # ── Attachments ──────────────────────────────────────────────────────

    @export(record=NoteAttachmentRecord)
    def attachments(self) -> Iterator[NoteAttachmentRecord]:
        """Parse note attachments (images, files, etc.)."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_attachments(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing note attachments at %s: %s", db_path, e)

    def _parse_attachments(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT Z_PK, ZCREATIONDATE, ZMODIFICATIONDATE, ZFILENAME,
                       ZTYPEUTI, ZTITLE, ZFILESIZE, ZNOTE, ZIDENTIFIER
                FROM ZICCLOUDSYNCINGOBJECT
                WHERE Z_ENT = (
                    SELECT Z_ENT FROM Z_PRIMARYKEY WHERE Z_NAME = 'ICAttachment'
                )
                AND ZFILENAME IS NOT NULL
                ORDER BY ZMODIFICATIONDATE DESC
            """)
            for row in cursor:
                yield NoteAttachmentRecord(
                    ts_created=_cocoa_ts(row["ZCREATIONDATE"]),
                    ts_modified=_cocoa_ts(row["ZMODIFICATIONDATE"]),
                    filename=row["ZFILENAME"] or "",
                    mime_type=row["ZTYPEUTI"] or "",
                    title=row["ZTITLE"] or "",
                    file_size=row["ZFILESIZE"] or 0,
                    note_id=row["ZNOTE"] or 0,
                    identifier=row["ZIDENTIFIER"] or "",
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()
