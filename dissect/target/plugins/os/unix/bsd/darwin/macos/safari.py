from __future__ import annotations

import plistlib
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


SafariHistoryRecord = TargetRecordDescriptor(
    "browser/safari/history",
    [
        ("datetime", "ts"),
        ("string", "url"),
        ("string", "title"),
        ("string", "url_domain"),
        ("varint", "visit_count"),
        ("boolean", "load_successful"),
        ("boolean", "synthesized"),
        ("varint", "redirect_source"),
        ("varint", "redirect_destination"),
        ("path", "source"),
    ],
)

SafariDownloadRecord = TargetRecordDescriptor(
    "browser/safari/download",
    [
        ("datetime", "ts"),
        ("string", "url"),
        ("path", "download_path"),
        ("varint", "download_size"),
        ("string", "mime_type"),
        ("boolean", "was_successful"),
        ("string", "sandbox_key"),
        ("path", "source"),
    ],
)

SafariBookmarkRecord = TargetRecordDescriptor(
    "browser/safari/bookmark",
    [
        ("string", "title"),
        ("string", "url"),
        ("string", "folder"),
        ("string", "uuid"),
        ("path", "source"),
    ],
)

SafariTopSiteRecord = TargetRecordDescriptor(
    "browser/safari/topsite",
    [
        ("string", "title"),
        ("string", "url"),
        ("path", "source"),
    ],
)

COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _parse_cocoa_timestamp(value):
    """Convert Cocoa/Core Data timestamp (seconds since 2001-01-01) to datetime."""
    if value:
        try:
            return COCOA_EPOCH + timedelta(seconds=value)
        except (OSError, OverflowError, ValueError):
            return COCOA_EPOCH
    return COCOA_EPOCH


def _read_plist(path):
    """Read a plist file from a dissect filesystem path."""
    with path.open("rb") as fh:
        return plistlib.loads(fh.read())


class SafariPlugin(Plugin):
    """Plugin to parse Safari browser artifacts on macOS.

    Parses:
    - History.db (browsing history)
    - Downloads.plist (download history)
    - Bookmarks.plist (bookmarks and reading list)
    - TopSites.plist (frequently visited sites)

    Usage::

        target-query --plugin-path plugins -f safari.history <target>
        target-query --plugin-path plugins -f safari.downloads <target>
        target-query --plugin-path plugins -f safari.bookmarks <target>
        target-query --plugin-path plugins -f safari.topsites <target>
    """

    __namespace__ = "safari"

    def __init__(self, target):
        super().__init__(target)
        self._safari_dirs = list(self.target.fs.path("/").glob("Users/*/Library/Safari"))

    def check_compatible(self) -> None:
        if not self._safari_dirs:
            raise UnsupportedPluginError("No Safari data directory found")

    def _find_file(self, filename):
        """Yield (path) for each user's Safari directory containing the file."""
        for safari_dir in self._safari_dirs:
            path = safari_dir.joinpath(filename)
            if path.exists():
                yield path

    # ── History ──────────────────────────────────────────────────────────

    @export(record=SafariHistoryRecord)
    def history(self) -> Iterator[SafariHistoryRecord]:
        """Parse Safari browsing history from History.db."""
        for db_path in self._find_file("History.db"):
            try:
                yield from self._parse_history_db(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing Safari history at %s: %s", db_path, e)

    def _parse_history_db(self, db_path):
        with db_path.open("rb") as fh:
            db_bytes = fh.read()

        with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
            tmp.write(db_bytes)
            tmp.flush()

            for suffix in ["-wal", "-shm"]:
                src = db_path.parent.joinpath(db_path.name + suffix)
                if src.exists():
                    with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                        df.write(sf.read())

            conn = sqlite3.connect(tmp.name)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    v.visit_time,
                    v.title,
                    v.load_successful,
                    v.synthesized,
                    v.redirect_source,
                    v.redirect_destination,
                    i.url,
                    i.domain_expansion,
                    i.visit_count
                FROM history_visits v
                JOIN history_items i ON v.history_item = i.id
                ORDER BY v.visit_time DESC
            """)

            for row in cursor:
                yield SafariHistoryRecord(
                    ts=_parse_cocoa_timestamp(row["visit_time"]),
                    url=row["url"] or "",
                    title=row["title"] or "",
                    url_domain=row["domain_expansion"] or "",
                    visit_count=row["visit_count"] or 0,
                    load_successful=bool(row["load_successful"]),
                    synthesized=bool(row["synthesized"]),
                    redirect_source=row["redirect_source"] or 0,
                    redirect_destination=row["redirect_destination"] or 0,
                    source=db_path,
                    _target=self.target,
                )

            conn.close()

    # ── Downloads ────────────────────────────────────────────────────────

    @export(record=SafariDownloadRecord)
    def downloads(self) -> Iterator[SafariDownloadRecord]:
        """Parse Safari download history from Downloads.plist."""
        for plist_path in self._find_file("Downloads.plist"):
            try:
                yield from self._parse_downloads(plist_path)
            except Exception as e:
                self.target.log.warning("Error parsing Safari downloads at %s: %s", plist_path, e)

    def _parse_downloads(self, plist_path):
        data = _read_plist(plist_path)

        for entry in data.get("DownloadHistory", []):
            # DownloadEntryDateAddedKey is a Cocoa timestamp or datetime
            ts = entry.get("DownloadEntryDateAddedKey")
            if isinstance(ts, (int, float)):
                ts = _parse_cocoa_timestamp(ts)
            elif not isinstance(ts, datetime):
                ts = COCOA_EPOCH

            yield SafariDownloadRecord(
                ts=ts,
                url=entry.get("DownloadEntryURL", entry.get("DownloadEntryURLString", "")),
                download_path=entry.get("DownloadEntryPath", entry.get("DownloadEntryFilename", "")),
                download_size=entry.get("DownloadEntryProgressTotalToLoad", 0),
                mime_type=entry.get("DownloadEntryMIMEType", ""),
                was_successful=not entry.get("DownloadEntryRemoveWhenDoneKey", False),
                sandbox_key=entry.get("DownloadEntrySandboxExtensionKey", ""),
                source=plist_path,
                _target=self.target,
            )

    # ── Bookmarks ────────────────────────────────────────────────────────

    @export(record=SafariBookmarkRecord)
    def bookmarks(self) -> Iterator[SafariBookmarkRecord]:
        """Parse Safari bookmarks from Bookmarks.plist."""
        for plist_path in self._find_file("Bookmarks.plist"):
            try:
                yield from self._parse_bookmarks(plist_path)
            except Exception as e:
                self.target.log.warning("Error parsing Safari bookmarks at %s: %s", plist_path, e)

    def _parse_bookmarks(self, plist_path):
        data = _read_plist(plist_path)
        yield from self._walk_bookmarks(data, "", plist_path)

    def _walk_bookmarks(self, node, folder, plist_path):
        """Recursively walk the bookmark tree."""
        bookmark_type = node.get("WebBookmarkType", "")

        if bookmark_type == "WebBookmarkTypeLeaf":
            uri_dict = node.get("URIDictionary", {})
            yield SafariBookmarkRecord(
                title=uri_dict.get("title", node.get("Title", "")),
                url=node.get("URLString", ""),
                folder=folder,
                uuid=node.get("WebBookmarkUUID", ""),
                source=plist_path,
                _target=self.target,
            )

        children = node.get("Children", [])
        current_folder = node.get("Title", folder)
        # Map internal names to readable names
        folder_names = {
            "BookmarksBar": "Favorites Bar",
            "BookmarksMenu": "Bookmarks Menu",
            "com.apple.ReadingList": "Reading List",
        }
        current_folder = folder_names.get(current_folder, current_folder)

        for child in children:
            yield from self._walk_bookmarks(child, current_folder, plist_path)

    # ── Top Sites ────────────────────────────────────────────────────────

    @export(record=SafariTopSiteRecord)
    def topsites(self) -> Iterator[SafariTopSiteRecord]:
        """Parse Safari frequently visited sites from TopSites.plist."""
        for plist_path in self._find_file("TopSites.plist"):
            try:
                yield from self._parse_topsites(plist_path)
            except Exception as e:
                self.target.log.warning("Error parsing Safari topsites at %s: %s", plist_path, e)

    def _parse_topsites(self, plist_path):
        data = _read_plist(plist_path)

        for entry in data.get("TopSites", []):
            yield SafariTopSiteRecord(
                title=entry.get("TopSiteTitle", ""),
                url=entry.get("TopSiteURLString", ""),
                source=plist_path,
                _target=self.target,
            )
