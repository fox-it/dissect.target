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


COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

FaceTimeLinkRecord = TargetRecordDescriptor(
    "macos/facetime/links",
    [
        ("datetime", "creation_date"),
        ("datetime", "expiration_date"),
        ("datetime", "deletion_date"),
        ("string", "link_name"),
        ("string", "pseudonym"),
        ("boolean", "activated"),
        ("varint", "lifetime_type"),
        ("varint", "delete_reason"),
        ("path", "source"),
    ],
)

FaceTimeHandleRecord = TargetRecordDescriptor(
    "macos/facetime/handles",
    [
        ("string", "handle_value"),
        ("string", "normalized_value"),
        ("varint", "handle_type"),
        ("string", "country_code"),
        ("path", "source"),
    ],
)


class FaceTimePlugin(Plugin):
    """Plugin to parse macOS FaceTime conversation links and handles.

    Parses FaceTime.sqlite3 which contains FaceTime link invitations,
    conversation links, and associated phone numbers/handles.

    Location: ~/Library/Application Support/FaceTime/FaceTime.sqlite3
    """

    __namespace__ = "facetime"

    DB_GLOB = "Users/*/Library/Application Support/FaceTime/FaceTime.sqlite3"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.DB_GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No FaceTime database found")

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

    def _cocoa_to_dt(self, ts):
        if ts is not None and ts > 0:
            try:
                return COCOA_EPOCH + timedelta(seconds=ts)
            except (ValueError, OverflowError):
                pass
        return None

    @export(record=FaceTimeLinkRecord)
    def links(self) -> Iterator[FaceTimeLinkRecord]:
        """Parse FaceTime conversation links."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_links(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing FaceTime links at %s: %s", db_path, e)

    def _parse_links(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(ZCONVERSATIONLINK)")
            columns = [col["name"] for col in cursor.fetchall()]
            if not columns:
                return
            cursor.execute("SELECT * FROM ZCONVERSATIONLINK")
            for row in cursor:
                yield FaceTimeLinkRecord(
                    creation_date=self._cocoa_to_dt(row["ZCREATIONDATE"]) if "ZCREATIONDATE" in columns else None,
                    expiration_date=self._cocoa_to_dt(row["ZEXPIRATIONDATE"]) if "ZEXPIRATIONDATE" in columns else None,
                    deletion_date=self._cocoa_to_dt(row["ZDELETIONDATE"]) if "ZDELETIONDATE" in columns else None,
                    link_name=row["ZNAME"] if "ZNAME" in columns and row["ZNAME"] else "",
                    pseudonym=row["ZPSEUDONYM"] if "ZPSEUDONYM" in columns and row["ZPSEUDONYM"] else "",
                    activated=bool(row["ZACTIVATED"]) if "ZACTIVATED" in columns else False,
                    lifetime_type=row["ZLIFETIMETYPE"] if "ZLIFETIMETYPE" in columns else 0,
                    delete_reason=row["ZDELETEREASON"] if "ZDELETEREASON" in columns else 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    @export(record=FaceTimeHandleRecord)
    def handles(self) -> Iterator[FaceTimeHandleRecord]:
        """Parse FaceTime handles (phone numbers/identifiers)."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_handles(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing FaceTime handles at %s: %s", db_path, e)

    def _parse_handles(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(ZHANDLE)")
            columns = [col["name"] for col in cursor.fetchall()]
            if not columns:
                return
            cursor.execute("SELECT * FROM ZHANDLE")
            for row in cursor:
                yield FaceTimeHandleRecord(
                    handle_value=row["ZVALUE"] if "ZVALUE" in columns and row["ZVALUE"] else "",
                    normalized_value=row["ZNORMALIZEDVALUE"]
                    if "ZNORMALIZEDVALUE" in columns and row["ZNORMALIZEDVALUE"]
                    else "",
                    handle_type=row["ZTYPE"] if "ZTYPE" in columns else 0,
                    country_code=row["ZISOCOUNTRYCODE"]
                    if "ZISOCOUNTRYCODE" in columns and row["ZISOCOUNTRYCODE"]
                    else "",
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()
