from __future__ import annotations

import json
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from dissect.database.exception import Error as DBError
from dissect.database.sqlite3 import SQLite3

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.browser.browser import (
    GENERIC_BOOKMARK_RECORD_FIELDS,
    GENERIC_COOKIE_FIELDS,
    GENERIC_DOWNLOAD_RECORD_FIELDS,
    GENERIC_HISTORY_RECORD_FIELDS,
    GENERIC_LOCAL_STORAGE_FIELDS,
    BrowserPlugin,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target


class LadybirdPlugin(BrowserPlugin):
    """Ladybird browser plugin.

    Tested with Ladybird version 2026.47.7

    References:
        - https://ladybird.org
        - https://github.com/LadybirdBrowser/ladybird
    """

    __namespace__ = "ladybird"

    USER_DATA_DIRS = (
        # Windows
        "AppData/Local/Ladybird",
        # Linux
        ".local/share/Ladybird",
        ".data/Ladybird",
        "config/non-packaged/data",
        # macOS
        "Library/Application Support/Ladybird",
    )
    """Contains ``History.db``, ``Ladybird.db`` and ``Sessions.db``."""

    USER_CONFIG_DIRS = (
        # Windows
        "AppData/Roaming/Ladybird",
        # Linux
        ".config/Ladybird",
        "config/settings/Ladybird",
        # macOS
        "Library/Preferences/Ladybird",
    )
    """Contains ``Bookmarks.json``, ``Permissions.json`` and ``Settings.json``."""

    BrowserCookieRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/ladybird/cookie", GENERIC_COOKIE_FIELDS
    )

    BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/ladybird/download", GENERIC_DOWNLOAD_RECORD_FIELDS
    )

    BrowserLocalStorageRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/ladybird/localstorage", GENERIC_LOCAL_STORAGE_FIELDS
    )

    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/ladybird/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    BrowserBookmarkRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/ladybird/bookmark", GENERIC_BOOKMARK_RECORD_FIELDS
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.installs = list(self.find_installs())
        self.dbs = list(self._iter_db())

    def find_installs(self) -> Iterator[tuple[UserDetails, Path]]:
        """Find Ladybird user install data directories on the target.

        References:
            - https://github.com/LadybirdBrowser/ladybird/blob/master/Libraries/LibCore/StandardPaths.cpp
            - https://github.com/LadybirdBrowser/ladybird/blob/master/Libraries/LibDatabase/Database.cpp
        """
        for user_details in self.target.user_details.all_with_home():
            for dir in self.USER_DATA_DIRS + self.USER_CONFIG_DIRS:
                if (profiles := user_details.home_path.joinpath(dir).joinpath("Profiles")).is_dir():
                    for profile in profiles.iterdir():
                        yield user_details, profile

    def _iter_db(self) -> Iterator[tuple[UserDetails, Path, SQLite3]]:
        """Search Ladybird user install data directories for ``Ladybird.db`` databases."""
        for user_details, install in self.installs:
            for file_name in ("Ladybird.db", "History.db", "Session.db"):
                if (db_file := install.joinpath(file_name)).is_file():
                    try:
                        db = SQLite3(db_file)
                    except DBError as e:
                        self.target.log.warning("Unable to read %s: %s", db_file, e)
                        self.target.log.debug("", exc_info=e)
                        continue
                    yield user_details, db_file, db

    def check_compatible(self) -> None:
        if not self.installs:
            raise UnsupportedPluginError("No Ladybird data directories found on target")

    @export(record=BrowserCookieRecord)
    def cookies(self) -> Iterator[BrowserCookieRecord]:
        """Yield cookie browser records from Ladybird."""
        for user_details, db_file, db in self.dbs:
            if db_file.name != "Ladybird.db":
                continue

            if not (table := db.table("Cookies")):
                self.target.log.warning("Database %s does not have table 'Cookies'", db)
                continue

            for row in table.rows():
                yield self.BrowserCookieRecord(
                    ts_created=row.get("creation_time", 0) / 1000,
                    ts_last_accessed=row.get("last_access_time", 0) / 1000,
                    browser="ladybird",
                    name=row.get("name"),
                    value=row.get("value"),
                    host=row.get("domain"),
                    path=row.get("path"),
                    expiry=row.get("expiry_time", 0) / 1000,
                    is_secure=row.get("secure") == 1,
                    is_http_only=row.get("http_only") == 1,
                    same_site=row.get("host_only") == 1,
                    source=db_file,
                    _user=user_details.user,
                    _target=self.target,
                )

    @export(record=BrowserDownloadRecord)
    def downloads(self) -> Iterator[BrowserDownloadRecord]:
        """Yield session download records from Ladybird.

        This table only includes downloads from a live Ladybird session.
        """
        for user_details, db_file, db in self.dbs:
            if db_file.name != "Ladybird.db":
                continue
            if not (table := db.table("Downloads")):
                self.target.log.warning("Database %s does not have table 'Downloads'", db)
                continue

            for row in table.rows():
                yield self.BrowserDownloadRecord(
                    ts_start=row.get("created_time", 0) / 1000,
                    ts_end=row.get("updated_time", 0) / 1000,
                    browser="ladybird",
                    id=row.get("id"),
                    path=row.get("destination"),
                    url=row.get("url"),
                    size=row.get("total_size"),
                    source=db_file,
                    _user=user_details.user,
                    _target=self.target,
                )

    @export(record=BrowserLocalStorageRecord)
    def localstorage(self) -> Iterator[BrowserLocalStorageRecord]:
        """Yield LocalStorage browser records from Ladybird."""
        for user_details, db_file, db in self.dbs:
            if db_file.name != "Ladybird.db":
                continue
            if not (table := db.table("WebStorage")):
                self.target.log.warning("Database %s does not have table 'WebStorage'", db)
                continue

            for row in table.rows():
                yield self.BrowserLocalStorageRecord(
                    ts_created=None,
                    ts_last_modified=None,
                    ts_last_accessed=row.get("last_access_time", 0) / 1000,
                    browser="ladybird",
                    host=row.get("storage_key"),
                    key=row.get("bottle_key"),
                    value=row.get("bottle_value"),
                    source=db_file,
                    _user=user_details.user,
                    _target=self.target,
                )

    @export(record=BrowserHistoryRecord)
    def history(self) -> Iterator[BrowserHistoryRecord]:
        """Yield history records from Ladybird."""
        for user_details, db_file, db in self.dbs:
            if db_file.name != "History.db":
                continue
            if not (table := db.table("History")):
                self.target.log.warning("Database %s does not have table 'History'", db)
                continue

            for row in table.rows():
                yield self.BrowserHistoryRecord(
                    ts=row.get("last_visited_time", 0) / 1000,
                    browser="ladybird",
                    url=row.get("url"),
                    title=row.get("title"),
                    host=urlparse(row.get("url")).hostname,
                    visit_count=row.get("visit_count"),
                    source=db_file,
                    _user=user_details.user,
                    _target=self.target,
                )

    @export(record=BrowserBookmarkRecord)
    def bookmarks(self) -> Iterator[BrowserBookmarkRecord]:
        """Yield bookmark records from Ladybird."""
        for user_details, install in self.installs:
            if (bookmarks_path := install.joinpath("Bookmarks.json")).is_file():
                try:
                    bookmarks = json.loads(bookmarks_path.read_text())
                except json.JSONDecodeError as e:
                    self.target.log.warning("Failed to read %s: %s", bookmarks_path, e)
                    self.target.log.debug("", exc_info=e)
                    continue

                for item in bookmarks.get("items", []):
                    yield self.BrowserBookmarkRecord(
                        ts_added=item.get("dateAdded", 0) / 1000,
                        ts_modified=item.get("lastModified", 0) / 1000,
                        url=item.get("url"),
                        title=item.get("title"),
                        id=item.get("id"),
                        source=bookmarks_path,
                        _user=user_details.user,
                        _target=self.target,
                    )
