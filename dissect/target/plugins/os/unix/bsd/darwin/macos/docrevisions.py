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


UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _parse_ts(value):
    """Parse timestamp - DocumentRevisions uses Unix epoch, not Cocoa."""
    if value and isinstance(value, (int, float)) and value > 0:
        try:
            return UNIX_EPOCH + timedelta(seconds=value)
        except (OSError, OverflowError, ValueError):
            return UNIX_EPOCH
    return COCOA_EPOCH


def _get_columns(cursor, table):
    """Get column names for a table."""
    cursor.execute(f"PRAGMA table_info({table})")
    return [row[1] for row in cursor.fetchall()]


DocumentRevisionRecord = TargetRecordDescriptor(
    "macos/docrevisions/generation",
    [
        ("datetime", "ts_created"),
        ("string", "file_path"),
        ("string", "file_name"),
        ("string", "generation_path"),
        ("varint", "generation_id"),
        ("varint", "file_row_id"),
        ("varint", "storage_id"),
        ("string", "generation_status"),
        ("path", "source"),
    ],
)

DocumentRevisionFileRecord = TargetRecordDescriptor(
    "macos/docrevisions/file",
    [
        ("string", "file_path"),
        ("string", "file_name"),
        ("varint", "file_row_id"),
        ("varint", "file_inode"),
        ("varint", "file_last_seen"),
        ("path", "source"),
    ],
)


class MacOSDocRevisionsPlugin(Plugin):
    """Plugin to parse macOS Document Revisions database.

    macOS Versions automatically saves versions of files as they are edited.
    The database tracks every file version, even after deletion.
    Requires root on live systems; works without restrictions on forensic images.

    Locations:
    - /.DocumentRevisions-V100/db-V1/db.sqlite
    - /System/Volumes/Data/.DocumentRevisions-V100/db-V1/db.sqlite
    - /Volumes/*/.DocumentRevisions-V100/db-V1/db.sqlite
    """

    __namespace__ = "docrevisions"

    DB_PATHS = [
        ".DocumentRevisions-V100/db-V1/db.sqlite",
        "%2EDocumentRevisions-V100/db-V1/db.sqlite",
        "System/Volumes/Data/.DocumentRevisions-V100/db-V1/db.sqlite",
        "System/Volumes/Data/%2EDocumentRevisions-V100/db-V1/db.sqlite",
    ]

    DB_GLOBS = [
        "Volumes/*/.DocumentRevisions-V100/db-V1/db.sqlite",
        "Volumes/*/%2EDocumentRevisions-V100/db-V1/db.sqlite",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = []
        for rel_path in self.DB_PATHS:
            path = self.target.fs.path(f"/{rel_path}")
            if path.exists():
                self._db_paths.append(path)
        for pattern in self.DB_GLOBS:
            for path in self.target.fs.path("/").glob(pattern):
                if path.exists():
                    self._db_paths.append(path)

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No DocumentRevisions database found")

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

    @export(record=DocumentRevisionRecord)
    def generations(self) -> Iterator[DocumentRevisionRecord]:
        """Parse document revision generations (file versions)."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_generations(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing DocumentRevisions at %s: %s", db_path, e)

    def _parse_generations(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            tables = [row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

            if "generations" not in tables:
                return

            gen_cols = _get_columns(cursor, "generations")
            has_files = "files" in tables

            if has_files:
                file_cols = _get_columns(cursor, "files")

                # Build SELECT dynamically based on available columns
                g_select = ["g.generation_id", "g.generation_path", "g.generation_status"]
                g_select.append(
                    "g.generation_add_time" if "generation_add_time" in gen_cols else "NULL as generation_add_time"
                )
                g_select.append(
                    "g.generation_storage_id" if "generation_storage_id" in gen_cols else "0 as generation_storage_id"
                )

                f_select = []
                f_select.append("f.file_path" if "file_path" in file_cols else "'' as file_path")
                f_select.append("f.file_name" if "file_name" in file_cols else "'' as file_name")
                f_select.append("f.file_row_id" if "file_row_id" in file_cols else "0 as file_row_id")

                # Determine JOIN column
                if "file_row_id" in gen_cols and "file_row_id" in file_cols:
                    join_clause = "LEFT JOIN files f ON g.file_row_id = f.file_row_id"
                else:
                    join_clause = "LEFT JOIN files f ON g.rowid = f.file_row_id"

                query = f"SELECT {', '.join(g_select)}, {', '.join(f_select)} FROM generations g {join_clause} ORDER BY g.generation_add_time DESC" # noqa: E501
            else:
                # Generations only, no files table
                g_select = ["generation_id", "generation_path", "generation_status"]
                g_select.append(
                    "generation_add_time" if "generation_add_time" in gen_cols else "NULL as generation_add_time"
                )
                g_select.append(
                    "generation_storage_id" if "generation_storage_id" in gen_cols else "0 as generation_storage_id"
                )
                g_select.extend(["'' as file_path", "'' as file_name", "0 as file_row_id"])
                query = f"SELECT {', '.join(g_select)} FROM generations ORDER BY generation_add_time DESC"

            cursor.execute(query)

            for row in cursor:
                yield DocumentRevisionRecord(
                    ts_created=_parse_ts(row["generation_add_time"]),
                    file_path=row["file_path"] or "",
                    file_name=row["file_name"] or "",
                    generation_path=row["generation_path"] or "",
                    generation_id=row["generation_id"] or 0,
                    file_row_id=row["file_row_id"] or 0,
                    storage_id=row["generation_storage_id"] or 0,
                    generation_status=str(row["generation_status"] or ""),
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    @export(record=DocumentRevisionFileRecord)
    def files(self) -> Iterator[DocumentRevisionFileRecord]:
        """Parse tracked files from the DocumentRevisions database."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_files(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing DocumentRevisions files at %s: %s", db_path, e)

    def _parse_files(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            tables = [row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

            if "files" not in tables:
                return

            cols = _get_columns(cursor, "files")

            select = []
            select.append("file_path" if "file_path" in cols else "'' as file_path")
            select.append("file_name" if "file_name" in cols else "'' as file_name")
            select.append("file_row_id" if "file_row_id" in cols else "rowid as file_row_id")
            select.append("file_inode" if "file_inode" in cols else "0 as file_inode")
            select.append("file_last_seen" if "file_last_seen" in cols else "0 as file_last_seen")

            order = "file_last_seen DESC" if "file_last_seen" in cols else "file_row_id DESC"
            cursor.execute(f"SELECT {', '.join(select)} FROM files ORDER BY {order}")

            for row in cursor:
                yield DocumentRevisionFileRecord(
                    file_path=row["file_path"] or "",
                    file_name=row["file_name"] or "",
                    file_row_id=row["file_row_id"] or 0,
                    file_inode=row["file_inode"] or 0,
                    file_last_seen=row["file_last_seen"] or 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()
