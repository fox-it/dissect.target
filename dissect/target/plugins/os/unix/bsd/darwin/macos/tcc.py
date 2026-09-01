from __future__ import annotations

import plistlib
import sqlite3
import tempfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


TCCAccessRecord = TargetRecordDescriptor(
    "macos/tcc/access",
    [
        ("datetime", "ts"),
        ("string", "service"),
        ("string", "client"),
        ("varint", "client_type"),
        ("varint", "auth_value"),
        ("varint", "auth_reason"),
        ("varint", "auth_version"),
        ("string", "indirect_object_identifier"),
        ("varint", "flags"),
        ("datetime", "last_reminded"),
        ("string", "tcc_scope"),
        ("path", "source"),
    ],
)

TCCExpiredRecord = TargetRecordDescriptor(
    "macos/tcc/expired",
    [
        ("datetime", "ts"),
        ("datetime", "expired_at"),
        ("string", "service"),
        ("string", "client"),
        ("varint", "client_type"),
        ("string", "tcc_scope"),
        ("path", "source"),
    ],
)

LocationClientRecord = TargetRecordDescriptor(
    "macos/tcc/location_clients",
    [
        ("string", "bundle_id"),
        ("string", "authorization"),
        ("boolean", "authorized"),
        ("string", "bundle_path"),
        ("path", "source"),
    ],
)


class TCCPlugin(Plugin):
    """Plugin to parse macOS TCC (Transparency, Consent, and Control) databases.

    Parses permission grants/denials for privacy-sensitive resources like
    camera, microphone, contacts, photos, etc.

    Locations:
    - /Library/Application Support/com.apple.TCC/TCC.db (system)
    - ~/Library/Application Support/com.apple.TCC/TCC.db (per-user)
    - /private/var/db/locationd/clients.plist
    """

    __namespace__ = "tcc"

    SYSTEM_DB = "Library/Application Support/com.apple.TCC/TCC.db"
    USER_DB = "Users/*/Library/Application Support/com.apple.TCC/TCC.db"
    LOCATION_PLIST = "private/var/db/locationd/clients.plist"

    def __init__(self, target):
        super().__init__(target)
        self._system_dbs = list(self.target.fs.path("/").glob(self.SYSTEM_DB))
        self._user_dbs = list(self.target.fs.path("/").glob(self.USER_DB))
        self._location_plists = list(self.target.fs.path("/").glob(self.LOCATION_PLIST))

    def check_compatible(self) -> None:
        if not self._system_dbs and not self._user_dbs and not self._location_plists:
            raise UnsupportedPluginError("No TCC databases or location plist found")

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

    def _unix_to_dt(self, ts):
        if ts and ts > 0:
            try:
                return datetime.fromtimestamp(ts, tz=timezone.utc)
            except (ValueError, OSError):
                pass
        return None

    def _scope_from_path(self, db_path):
        path_str = str(db_path)
        if "/Users/" in path_str:
            parts = path_str.split("/Users/")
            if len(parts) > 1:
                return parts[1].split("/")[0]
        return "system"

    @export(record=TCCAccessRecord)
    def access(self) -> Iterator[TCCAccessRecord]:
        """Parse TCC access permissions (grants/denials) from TCC.db."""
        for db_path in self._system_dbs + self._user_dbs:
            try:
                yield from self._parse_access(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing TCC access at %s: %s", db_path, e)

    def _parse_access(self, db_path):
        scope = self._scope_from_path(db_path)
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(access)")
            columns = [col["name"] for col in cursor.fetchall()]
            if not columns:
                return
            cursor.execute("SELECT * FROM access")
            for row in cursor:
                last_modified = row["last_modified"] if "last_modified" in columns else None
                last_reminded = row["last_reminded"] if "last_reminded" in columns else None
                yield TCCAccessRecord(
                    ts=self._unix_to_dt(last_modified),
                    service=row["service"] if "service" in columns else "",
                    client=row["client"] if "client" in columns else "",
                    client_type=row["client_type"] if "client_type" in columns else 0,
                    auth_value=row["auth_value"] if "auth_value" in columns else 0,
                    auth_reason=row["auth_reason"] if "auth_reason" in columns else 0,
                    auth_version=row["auth_version"] if "auth_version" in columns else 0,
                    indirect_object_identifier=row["indirect_object_identifier"]
                    if "indirect_object_identifier" in columns
                    else "",
                    flags=row["flags"] if "flags" in columns else 0,
                    last_reminded=self._unix_to_dt(last_reminded),
                    tcc_scope=scope,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    @export(record=TCCExpiredRecord)
    def expired(self) -> Iterator[TCCExpiredRecord]:
        """Parse expired TCC permissions from TCC.db."""
        for db_path in self._system_dbs + self._user_dbs:
            try:
                yield from self._parse_expired(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing TCC expired at %s: %s", db_path, e)

    def _parse_expired(self, db_path):
        scope = self._scope_from_path(db_path)
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(expired)")
            columns = [col["name"] for col in cursor.fetchall()]
            if not columns:
                return
            cursor.execute("SELECT * FROM expired")
            for row in cursor:
                yield TCCExpiredRecord(
                    ts=self._unix_to_dt(row["last_modified"] if "last_modified" in columns else None),
                    expired_at=self._unix_to_dt(row["expired_at"] if "expired_at" in columns else None),
                    service=row["service"] if "service" in columns else "",
                    client=row["client"] if "client" in columns else "",
                    client_type=row["client_type"] if "client_type" in columns else 0,
                    tcc_scope=scope,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    @export(record=LocationClientRecord)
    def location_clients(self) -> Iterator[LocationClientRecord]:
        """Parse location services client authorizations from clients.plist."""
        for plist_path in self._location_plists:
            try:
                yield from self._parse_location(plist_path)
            except Exception as e:
                self.target.log.warning("Error parsing location clients at %s: %s", plist_path, e)

    def _parse_location(self, plist_path):
        with plist_path.open("rb") as fh:
            data = plistlib.loads(fh.read())
        for bundle_id, info in data.items():
            if not isinstance(info, dict):
                continue
            yield LocationClientRecord(
                bundle_id=bundle_id,
                authorization=info.get("Authorization", ""),
                authorized=bool(info.get("Authorized", False)),
                bundle_path=info.get("BundlePath", info.get("BundleId", "")),
                source=plist_path,
                _target=self.target,
            )
