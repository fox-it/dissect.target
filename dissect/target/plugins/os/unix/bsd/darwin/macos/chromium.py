from __future__ import annotations

import json
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


# Chromium timestamps: microseconds since 1601-01-01
CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _chromium_ts(value):
    if value and value > 0:
        try:
            return CHROMIUM_EPOCH + timedelta(microseconds=value)
        except (OSError, OverflowError, ValueError):
            return CHROMIUM_EPOCH
    return CHROMIUM_EPOCH


# ── Record Descriptors ───────────────────────────────────────────────────

ChromiumHistoryRecord = TargetRecordDescriptor(
    "browser/chromium/history",
    [
        ("datetime", "ts_last_visit"),
        ("datetime", "ts_visit"),
        ("string", "url"),
        ("string", "title"),
        ("varint", "visit_count"),
        ("varint", "typed_count"),
        ("boolean", "hidden"),
        ("varint", "visit_duration_us"),
        ("varint", "transition"),
        ("string", "browser_name"),
        ("path", "source"),
    ],
)

ChromiumDownloadRecord = TargetRecordDescriptor(
    "browser/chromium/download",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("string", "url"),
        ("string", "target_path"),
        ("string", "tab_url"),
        ("string", "referrer"),
        ("varint", "received_bytes"),
        ("varint", "total_bytes"),
        ("varint", "state"),
        ("varint", "danger_type"),
        ("string", "browser_name"),
        ("path", "source"),
    ],
)

ChromiumSearchRecord = TargetRecordDescriptor(
    "browser/chromium/search",
    [
        ("datetime", "ts_last_visit"),
        ("string", "search_term"),
        ("string", "url"),
        ("string", "title"),
        ("string", "browser_name"),
        ("path", "source"),
    ],
)

ChromiumBookmarkRecord = TargetRecordDescriptor(
    "browser/chromium/bookmark",
    [
        ("datetime", "ts_added"),
        ("datetime", "ts_last_used"),
        ("string", "title"),
        ("string", "url"),
        ("string", "folder"),
        ("string", "browser_name"),
        ("path", "source"),
    ],
)

ChromiumCookieRecord = TargetRecordDescriptor(
    "browser/chromium/cookie",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_expires"),
        ("datetime", "ts_last_access"),
        ("string", "host_key"),
        ("string", "name"),
        ("string", "cookie_path"),
        ("boolean", "is_secure"),
        ("boolean", "is_httponly"),
        ("varint", "priority"),
        ("string", "browser_name"),
        ("path", "source"),
    ],
)

ChromiumLoginRecord = TargetRecordDescriptor(
    "browser/chromium/login",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_last_used"),
        ("string", "origin_url"),
        ("string", "action_url"),
        ("string", "username"),
        ("varint", "times_used"),
        ("string", "browser_name"),
        ("path", "source"),
    ],
)

ChromiumTopSiteRecord = TargetRecordDescriptor(
    "browser/chromium/topsite",
    [
        ("string", "url"),
        ("string", "title"),
        ("string", "browser_name"),
        ("path", "source"),
    ],
)

# Chromium browser profile locations on macOS
BROWSER_PROFILES = {
    "Chrome": "Library/Application Support/Google/Chrome",
    "Brave": "Library/Application Support/BraveSoftware/Brave-Browser",
    "Edge": "Library/Application Support/Microsoft Edge",
    "Chromium": "Library/Application Support/Chromium",
    "Opera": "Library/Application Support/com.operasoftware.Opera",
    "Vivaldi": "Library/Application Support/Vivaldi",
}

# Also check system-wide
SYSTEM_BROWSER_PROFILES = {
    "Chrome": "Applications/Google Chrome.app/../../../Library/Application Support/Google/Chrome",
}


class ChromiumBrowserPlugin(Plugin):
    """Plugin to parse Chromium-based browser data (Chrome, Brave, Edge, etc.).

    Parses history, downloads, searches, bookmarks, cookies, logins, and top sites
    from any Chromium-based browser on macOS.

    Locations: ~/Library/Application Support/{Google/Chrome,BraveSoftware/Brave-Browser,Microsoft Edge,...}
    """

    __namespace__ = "chromium"

    def __init__(self, target):
        super().__init__(target)
        self._profiles = []  # (browser_name, profile_path)

        for browser_name, rel_path in BROWSER_PROFILES.items():
            for profile_dir in self.target.fs.path("/").glob(f"Users/*/{rel_path}"):
                if profile_dir.is_dir():
                    # Find profile subdirs (Default, Profile 1, etc.)
                    for sub in profile_dir.iterdir():
                        if sub.is_dir() and (sub.joinpath("History").exists() or sub.joinpath("Bookmarks").exists()):
                            self._profiles.append((browser_name, sub))

    def check_compatible(self) -> None:
        if not self._profiles:
            raise UnsupportedPluginError("No Chromium-based browser data found")

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
        """Yield (browser_name, db_path, conn, tmp) for each profile containing filename."""
        for browser_name, profile_path in self._profiles:
            db_path = profile_path.joinpath(filename)
            if not db_path.exists():
                continue
            try:
                conn, tmp = self._open_db(db_path)
                yield browser_name, db_path, conn, tmp
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", db_path, e)

    # ── History ──────────────────────────────────────────────────────────

    @export(record=ChromiumHistoryRecord)
    def history(self) -> Iterator[ChromiumHistoryRecord]:
        """Parse browsing history from Chromium-based browsers."""
        for browser_name, db_path, conn, tmp in self._iter_db("History"):
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT u.url, u.title, u.visit_count, u.typed_count, u.hidden,
                           u.last_visit_time,
                           v.visit_time, v.visit_duration, v.transition
                    FROM visits v
                    JOIN urls u ON v.url = u.id
                    ORDER BY v.visit_time DESC
                """)
                for row in cursor:
                    yield ChromiumHistoryRecord(
                        ts_last_visit=_chromium_ts(row["last_visit_time"]),
                        ts_visit=_chromium_ts(row["visit_time"]),
                        url=row["url"] or "",
                        title=row["title"] or "",
                        visit_count=row["visit_count"] or 0,
                        typed_count=row["typed_count"] or 0,
                        hidden=bool(row["hidden"]),
                        visit_duration_us=row["visit_duration"] or 0,
                        transition=row["transition"] or 0,
                        browser_name=browser_name,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s history: %s", browser_name, e)
            finally:
                conn.close()
                tmp.close()

    # ── Downloads ────────────────────────────────────────────────────────

    @export(record=ChromiumDownloadRecord)
    def downloads(self) -> Iterator[ChromiumDownloadRecord]:
        """Parse download history from Chromium-based browsers."""
        for browser_name, db_path, conn, tmp in self._iter_db("History"):
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT d.start_time, d.end_time, d.target_path, d.tab_url,
                           d.referrer, d.received_bytes, d.total_bytes,
                           d.state, d.danger_type,
                           dc.url
                    FROM downloads d
                    LEFT JOIN downloads_url_chains dc ON dc.id = d.id AND dc.chain_index = 0
                    ORDER BY d.start_time DESC
                """)
                for row in cursor:
                    yield ChromiumDownloadRecord(
                        ts_start=_chromium_ts(row["start_time"]),
                        ts_end=_chromium_ts(row["end_time"]),
                        url=row["url"] or "",
                        target_path=row["target_path"] or "",
                        tab_url=row["tab_url"] or "",
                        referrer=row["referrer"] or "",
                        received_bytes=row["received_bytes"] or 0,
                        total_bytes=row["total_bytes"] or 0,
                        state=row["state"] or 0,
                        danger_type=row["danger_type"] or 0,
                        browser_name=browser_name,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s downloads: %s", browser_name, e)
            finally:
                conn.close()
                tmp.close()

    # ── Search terms ─────────────────────────────────────────────────────

    @export(record=ChromiumSearchRecord)
    def searches(self) -> Iterator[ChromiumSearchRecord]:
        """Parse keyword search terms from Chromium-based browsers."""
        for browser_name, db_path, conn, tmp in self._iter_db("History"):
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT k.term, u.url, u.title, u.last_visit_time
                    FROM keyword_search_terms k
                    JOIN urls u ON k.url_id = u.id
                    ORDER BY u.last_visit_time DESC
                """)
                for row in cursor:
                    yield ChromiumSearchRecord(
                        ts_last_visit=_chromium_ts(row["last_visit_time"]),
                        search_term=row["term"] or "",
                        url=row["url"] or "",
                        title=row["title"] or "",
                        browser_name=browser_name,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s searches: %s", browser_name, e)
            finally:
                conn.close()
                tmp.close()

    # ── Bookmarks ────────────────────────────────────────────────────────

    @export(record=ChromiumBookmarkRecord)
    def bookmarks(self) -> Iterator[ChromiumBookmarkRecord]:
        """Parse bookmarks from Chromium-based browsers."""
        for browser_name, profile_path in self._profiles:
            bm_path = profile_path.joinpath("Bookmarks")
            if not bm_path.exists():
                continue
            try:
                with bm_path.open("rb") as fh:
                    data = json.loads(fh.read())
                roots = data.get("roots", {})
                for root_name, root_node in roots.items():
                    if isinstance(root_node, dict):
                        yield from self._walk_bookmarks(root_node, root_name, browser_name, bm_path)
            except Exception as e:
                self.target.log.warning("Error parsing %s bookmarks: %s", browser_name, e)

    def _walk_bookmarks(self, node, folder, browser_name, source_path):
        if node.get("type") == "url":
            date_added = int(node.get("date_added", "0"))
            date_last_used = int(node.get("date_last_used", "0"))
            yield ChromiumBookmarkRecord(
                ts_added=_chromium_ts(date_added),
                ts_last_used=_chromium_ts(date_last_used),
                title=node.get("name", ""),
                url=node.get("url", ""),
                folder=folder,
                browser_name=browser_name,
                source=source_path,
                _target=self.target,
            )
        for child in node.get("children", []):
            child_folder = node.get("name", folder)
            yield from self._walk_bookmarks(child, child_folder, browser_name, source_path)

    # ── Cookies ──────────────────────────────────────────────────────────

    @export(record=ChromiumCookieRecord)
    def cookies(self) -> Iterator[ChromiumCookieRecord]:
        """Parse cookies from Chromium-based browsers."""
        for browser_name, db_path, conn, tmp in self._iter_db("Cookies"):
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT creation_utc, expires_utc, last_access_utc,
                           host_key, name, path, is_secure, is_httponly, priority
                    FROM cookies
                    ORDER BY last_access_utc DESC
                """)
                for row in cursor:
                    yield ChromiumCookieRecord(
                        ts_created=_chromium_ts(row["creation_utc"]),
                        ts_expires=_chromium_ts(row["expires_utc"]),
                        ts_last_access=_chromium_ts(row["last_access_utc"]),
                        host_key=row["host_key"] or "",
                        name=row["name"] or "",
                        cookie_path=row["path"] or "",
                        is_secure=bool(row["is_secure"]),
                        is_httponly=bool(row["is_httponly"]),
                        priority=row["priority"] or 0,
                        browser_name=browser_name,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s cookies: %s", browser_name, e)
            finally:
                conn.close()
                tmp.close()

    # ── Logins ───────────────────────────────────────────────────────────

    @export(record=ChromiumLoginRecord)
    def logins(self) -> Iterator[ChromiumLoginRecord]:
        """Parse saved login entries from Chromium-based browsers (no passwords extracted)."""
        for browser_name, db_path, conn, tmp in self._iter_db("Login Data"):
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT date_created, date_last_used, origin_url,
                           action_url, username_value, times_used
                    FROM logins
                    ORDER BY date_last_used DESC
                """)
                for row in cursor:
                    yield ChromiumLoginRecord(
                        ts_created=_chromium_ts(row["date_created"]),
                        ts_last_used=_chromium_ts(row["date_last_used"]),
                        origin_url=row["origin_url"] or "",
                        action_url=row["action_url"] or "",
                        username=row["username_value"] or "",
                        times_used=row["times_used"] or 0,
                        browser_name=browser_name,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s logins: %s", browser_name, e)
            finally:
                conn.close()
                tmp.close()

    # ── Top Sites ────────────────────────────────────────────────────────

    @export(record=ChromiumTopSiteRecord)
    def topsites(self) -> Iterator[ChromiumTopSiteRecord]:
        """Parse top sites from Chromium-based browsers."""
        for browser_name, db_path, conn, tmp in self._iter_db("Top Sites"):
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT url, title FROM top_sites")
                for row in cursor:
                    yield ChromiumTopSiteRecord(
                        url=row["url"] or "",
                        title=row["title"] or "",
                        browser_name=browser_name,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s top sites: %s", browser_name, e)
            finally:
                conn.close()
                tmp.close()
