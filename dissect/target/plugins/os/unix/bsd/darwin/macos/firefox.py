from __future__ import annotations

import json
import sqlite3
import tempfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


# Firefox timestamps: microseconds since 1970-01-01
FIREFOX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _ff_ts(value):
    """Convert Firefox PRTime (microseconds since Unix epoch) to datetime."""
    if value and value > 0:
        try:
            return datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return FIREFOX_EPOCH
    return FIREFOX_EPOCH


def _ff_ts_ms(value):
    """Convert milliseconds since Unix epoch to datetime."""
    if value and value > 0:
        try:
            return datetime.fromtimestamp(value / 1_000, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return FIREFOX_EPOCH
    return FIREFOX_EPOCH


def _ff_ts_s(value):
    """Convert seconds since Unix epoch to datetime."""
    if value and value > 0:
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return FIREFOX_EPOCH
    return FIREFOX_EPOCH


# ── Record Descriptors ───────────────────────────────────────────────────

FirefoxHistoryRecord = TargetRecordDescriptor(
    "browser/firefox/history",
    [
        ("datetime", "ts_visit"),
        ("datetime", "ts_last_visit"),
        ("string", "url"),
        ("string", "title"),
        ("varint", "visit_count"),
        ("varint", "typed"),
        ("varint", "visit_type"),
        ("string", "from_url"),
        ("path", "source"),
    ],
)

FirefoxDownloadRecord = TargetRecordDescriptor(
    "browser/firefox/download",
    [
        ("datetime", "ts_added"),
        ("datetime", "ts_modified"),
        ("string", "url"),
        ("string", "target_path"),
        ("string", "content_type"),
        ("varint", "max_bytes"),
        ("varint", "state"),
        ("path", "source"),
    ],
)

FirefoxSearchRecord = TargetRecordDescriptor(
    "browser/firefox/search",
    [
        ("datetime", "ts_first_visit"),
        ("datetime", "ts_last_visit"),
        ("string", "search_term"),
        ("string", "url"),
        ("string", "title"),
        ("path", "source"),
    ],
)

FirefoxBookmarkRecord = TargetRecordDescriptor(
    "browser/firefox/bookmark",
    [
        ("datetime", "ts_added"),
        ("datetime", "ts_modified"),
        ("string", "title"),
        ("string", "url"),
        ("string", "folder"),
        ("varint", "bookmark_type"),
        ("path", "source"),
    ],
)

FirefoxCookieRecord = TargetRecordDescriptor(
    "browser/firefox/cookie",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_last_accessed"),
        ("datetime", "ts_expiry"),
        ("string", "host"),
        ("string", "name"),
        ("string", "cookie_path"),
        ("boolean", "is_secure"),
        ("boolean", "is_httponly"),
        ("varint", "same_site"),
        ("path", "source"),
    ],
)

FirefoxLoginRecord = TargetRecordDescriptor(
    "browser/firefox/login",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_last_used"),
        ("datetime", "ts_password_changed"),
        ("string", "origin"),
        ("string", "form_action_origin"),
        ("string", "http_realm"),
        ("varint", "times_used"),
        ("path", "source"),
    ],
)

FirefoxFormHistoryRecord = TargetRecordDescriptor(
    "browser/firefox/formhistory",
    [
        ("datetime", "ts_first_used"),
        ("datetime", "ts_last_used"),
        ("string", "field_name"),
        ("string", "value"),
        ("varint", "times_used"),
        ("path", "source"),
    ],
)

FirefoxPermissionRecord = TargetRecordDescriptor(
    "browser/firefox/permission",
    [
        ("datetime", "ts_modified"),
        ("string", "origin"),
        ("string", "permission_type"),
        ("varint", "permission"),
        ("varint", "expire_type"),
        ("path", "source"),
    ],
)


class FirefoxBrowserPlugin(Plugin):
    """Plugin to parse Firefox browser data on macOS.

    Parses history, downloads, bookmarks, cookies, logins, form history,
    search terms, and site permissions from Firefox profiles.

    Location: ~/Library/Application Support/Firefox/Profiles/<profile>/
    """

    __namespace__ = "firefox"

    FIREFOX_GLOB = "Users/*/Library/Application Support/Firefox/Profiles/*"

    def __init__(self, target):
        super().__init__(target)
        self._profiles = []

        for profile_dir in self.target.fs.path("/").glob(self.FIREFOX_GLOB):
            if profile_dir.is_dir() and (
                profile_dir.joinpath("places.sqlite").exists() or profile_dir.joinpath("cookies.sqlite").exists()
            ):
                self._profiles.append(profile_dir)

    def check_compatible(self) -> None:
        if not self._profiles:
            raise UnsupportedPluginError("No Firefox profile data found")

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

    def _iter_db(self, filename):
        """Yield (db_path, conn, tmp) for each profile containing filename."""
        for profile_path in self._profiles:
            db_path = profile_path.joinpath(filename)
            if not db_path.exists():
                continue
            try:
                conn, tmp = self._open_db(db_path)
                yield db_path, conn, tmp
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", db_path, e)

    # ── History ──────────────────────────────────────────────────────────

    @export(record=FirefoxHistoryRecord)
    def history(self) -> Iterator[FirefoxHistoryRecord]:
        """Parse browsing history from Firefox places.sqlite."""
        for db_path, conn, tmp in self._iter_db("places.sqlite"):
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT h.visit_date, h.visit_type,
                           p.url, p.title, p.visit_count, p.typed,
                           p.last_visit_date,
                           p2.url AS from_url
                    FROM moz_historyvisits h
                    JOIN moz_places p ON h.place_id = p.id
                    LEFT JOIN moz_historyvisits h2 ON h.from_visit = h2.id
                    LEFT JOIN moz_places p2 ON h2.place_id = p2.id
                    ORDER BY h.visit_date DESC
                """)
                for row in cursor:
                    yield FirefoxHistoryRecord(
                        ts_visit=_ff_ts(row["visit_date"]),
                        ts_last_visit=_ff_ts(row["last_visit_date"]),
                        url=row["url"] or "",
                        title=row["title"] or "",
                        visit_count=row["visit_count"] or 0,
                        typed=row["typed"] or 0,
                        visit_type=row["visit_type"] or 0,
                        from_url=row["from_url"] or "",
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing Firefox history: %s", e)
            finally:
                conn.close()
                tmp.close()

    # ── Downloads ────────────────────────────────────────────────────────

    @export(record=FirefoxDownloadRecord)
    def downloads(self) -> Iterator[FirefoxDownloadRecord]:
        """Parse download history from Firefox places.sqlite (moz_annos)."""
        for db_path, conn, tmp in self._iter_db("places.sqlite"):
            try:
                cursor = conn.cursor()
                # Firefox stores downloads in moz_annos linked to moz_places
                # anno_attribute_id maps to moz_anno_attributes
                # Common attributes: downloads/destinationFileURI, downloads/metaData
                cursor.execute("""
                    SELECT p.url, p.visit_count,
                           a.dateAdded, a.lastModified, a.content,
                           aa.name AS anno_name
                    FROM moz_annos a
                    JOIN moz_places p ON a.place_id = p.id
                    JOIN moz_anno_attributes aa ON a.anno_attribute_id = aa.id
                    ORDER BY a.dateAdded DESC
                """)

                # Group annotations by place_id
                downloads = {}
                for row in cursor:
                    url = row["url"]
                    if url not in downloads:
                        downloads[url] = {
                            "url": url,
                            "ts_added": row["dateAdded"],
                            "ts_modified": row["lastModified"],
                        }
                    anno_name = row["anno_name"]
                    content = row["content"] or ""
                    if "destinationFileURI" in anno_name:
                        downloads[url]["target_path"] = content.replace("file://", "")
                    elif "metaData" in anno_name:
                        try:
                            meta = json.loads(content)
                            downloads[url]["state"] = meta.get("state", 0)
                            downloads[url]["max_bytes"] = meta.get("fileSize", 0)
                            downloads[url]["content_type"] = meta.get("contentType", "")
                        except (json.JSONDecodeError, TypeError):
                            pass

                for dl in downloads.values():
                    yield FirefoxDownloadRecord(
                        ts_added=_ff_ts(dl.get("ts_added")),
                        ts_modified=_ff_ts(dl.get("ts_modified")),
                        url=dl.get("url", ""),
                        target_path=dl.get("target_path", ""),
                        content_type=dl.get("content_type", ""),
                        max_bytes=dl.get("max_bytes", 0),
                        state=dl.get("state", 0),
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing Firefox downloads: %s", e)
            finally:
                conn.close()
                tmp.close()

    # ── Search terms (inputhistory) ──────────────────────────────────────

    @export(record=FirefoxSearchRecord)
    def searches(self) -> Iterator[FirefoxSearchRecord]:
        """Parse search terms from Firefox places.sqlite (moz_inputhistory)."""
        for db_path, conn, tmp in self._iter_db("places.sqlite"):
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT i.input, p.url, p.title,
                           p.last_visit_date,
                           (SELECT MIN(h.visit_date) FROM moz_historyvisits h
                            WHERE h.place_id = p.id) AS first_visit
                    FROM moz_inputhistory i
                    JOIN moz_places p ON i.place_id = p.id
                    ORDER BY p.last_visit_date DESC
                """)
                for row in cursor:
                    yield FirefoxSearchRecord(
                        ts_first_visit=_ff_ts(row["first_visit"]),
                        ts_last_visit=_ff_ts(row["last_visit_date"]),
                        search_term=row["input"] or "",
                        url=row["url"] or "",
                        title=row["title"] or "",
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing Firefox searches: %s", e)
            finally:
                conn.close()
                tmp.close()

    # ── Bookmarks ────────────────────────────────────────────────────────

    @export(record=FirefoxBookmarkRecord)
    def bookmarks(self) -> Iterator[FirefoxBookmarkRecord]:
        """Parse bookmarks from Firefox places.sqlite."""
        for db_path, conn, tmp in self._iter_db("places.sqlite"):
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT b.dateAdded, b.lastModified, b.title, b.type,
                           p.url,
                           parent_b.title AS folder
                    FROM moz_bookmarks b
                    LEFT JOIN moz_places p ON b.fk = p.id
                    LEFT JOIN moz_bookmarks parent_b ON b.parent = parent_b.id
                    WHERE b.type IN (1, 2)
                    ORDER BY b.dateAdded DESC
                """)
                for row in cursor:
                    yield FirefoxBookmarkRecord(
                        ts_added=_ff_ts(row["dateAdded"]),
                        ts_modified=_ff_ts(row["lastModified"]),
                        title=row["title"] or "",
                        url=row["url"] or "",
                        folder=row["folder"] or "",
                        bookmark_type=row["type"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing Firefox bookmarks: %s", e)
            finally:
                conn.close()
                tmp.close()

    # ── Cookies ──────────────────────────────────────────────────────────

    @export(record=FirefoxCookieRecord)
    def cookies(self) -> Iterator[FirefoxCookieRecord]:
        """Parse cookies from Firefox cookies.sqlite."""
        for db_path, conn, tmp in self._iter_db("cookies.sqlite"):
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT creationTime, lastAccessed, expiry,
                           host, name, path, isSecure, isHttpOnly, sameSite
                    FROM moz_cookies
                    ORDER BY lastAccessed DESC
                """)
                for row in cursor:
                    yield FirefoxCookieRecord(
                        ts_created=_ff_ts(row["creationTime"]),
                        ts_last_accessed=_ff_ts(row["lastAccessed"]),
                        ts_expiry=_ff_ts_s(row["expiry"]),
                        host=row["host"] or "",
                        name=row["name"] or "",
                        cookie_path=row["path"] or "",
                        is_secure=bool(row["isSecure"]),
                        is_httponly=bool(row["isHttpOnly"]),
                        same_site=row["sameSite"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing Firefox cookies: %s", e)
            finally:
                conn.close()
                tmp.close()

    # ── Logins ───────────────────────────────────────────────────────────

    @export(record=FirefoxLoginRecord)
    def logins(self) -> Iterator[FirefoxLoginRecord]:
        """Parse saved login entries from Firefox logins.json (no passwords extracted)."""
        for profile_path in self._profiles:
            logins_path = profile_path.joinpath("logins.json")
            if not logins_path.exists():
                continue
            try:
                with logins_path.open("rb") as fh:
                    data = json.loads(fh.read())

                for login in data.get("logins", []):
                    yield FirefoxLoginRecord(
                        ts_created=_ff_ts_ms(login.get("timeCreated")),
                        ts_last_used=_ff_ts_ms(login.get("timeLastUsed")),
                        ts_password_changed=_ff_ts_ms(login.get("timePasswordChanged")),
                        origin=login.get("origin", login.get("hostname", "")),
                        form_action_origin=login.get("formActionOrigin", login.get("formSubmitURL", "")),
                        http_realm=login.get("httpRealm") or "",
                        times_used=login.get("timesUsed", 0),
                        source=logins_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing Firefox logins: %s", e)

    # ── Form History ─────────────────────────────────────────────────────

    @export(record=FirefoxFormHistoryRecord)
    def formhistory(self) -> Iterator[FirefoxFormHistoryRecord]:
        """Parse form autofill history from Firefox formhistory.sqlite."""
        for db_path, conn, tmp in self._iter_db("formhistory.sqlite"):
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT fieldname, value, timesUsed, firstUsed, lastUsed
                    FROM moz_formhistory
                    ORDER BY lastUsed DESC
                """)
                for row in cursor:
                    yield FirefoxFormHistoryRecord(
                        ts_first_used=_ff_ts(row["firstUsed"]),
                        ts_last_used=_ff_ts(row["lastUsed"]),
                        field_name=row["fieldname"] or "",
                        value=row["value"] or "",
                        times_used=row["timesUsed"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing Firefox form history: %s", e)
            finally:
                conn.close()
                tmp.close()

    # ── Permissions ──────────────────────────────────────────────────────

    @export(record=FirefoxPermissionRecord)
    def permissions(self) -> Iterator[FirefoxPermissionRecord]:
        """Parse site permissions from Firefox permissions.sqlite."""
        for db_path, conn, tmp in self._iter_db("permissions.sqlite"):
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT origin, type, permission, expireType, modificationTime
                    FROM moz_perms
                    ORDER BY modificationTime DESC
                """)
                for row in cursor:
                    yield FirefoxPermissionRecord(
                        ts_modified=_ff_ts_ms(row["modificationTime"]),
                        origin=row["origin"] or "",
                        permission_type=row["type"] or "",
                        permission=row["permission"] or 0,
                        expire_type=row["expireType"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing Firefox permissions: %s", e)
            finally:
                conn.close()
                tmp.close()
