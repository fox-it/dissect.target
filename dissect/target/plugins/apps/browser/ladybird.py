from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.exception import Error as DBError
from dissect.database.sqlite3 import SQLite3

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.browser.browser import (
    GENERIC_COOKIE_FIELDS,
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

    Tested on Ladybird version 1.0 (2025-11-03 build).

    No browser history is currently saved by Ladybird.

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

    USER_CONFIG_DIRS = (
        # Windows
        "AppData/Roaming/Ladybird",
        # Linux
        ".config/Ladybird",
        "config/settings/Ladybird",
        # macOS
        "Library/Preferences/Ladybird",
    )

    BrowserCookieRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/ladybird/cookie", GENERIC_COOKIE_FIELDS
    )

    BrowserLocalStorageRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/ladybird/localstorage", GENERIC_LOCAL_STORAGE_FIELDS
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
            for dir in self.USER_DATA_DIRS:
                if (install := user_details.home_path.joinpath(dir)).is_dir():
                    yield user_details, install

    def _iter_db(self) -> Iterator[tuple[UserDetails, Path, SQLite3]]:
        """Search Ladybird user install data directories for ``Ladybird.db`` databases."""
        for user_details, install in self.installs:
            if (db_file := install.joinpath("Ladybird.db")).is_file():
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

    @export(record=BrowserLocalStorageRecord)
    def localstorage(self) -> Iterator[BrowserLocalStorageRecord]:
        """Yield LocalStorage browser records from Ladybird."""
        for user_details, db_file, db in self.dbs:
            if not (table := db.table("WebStorage")):
                self.target.log.warning("Database %s does not have table 'Cookies'", db)
                continue

            stat = db_file.lstat()

            for row in table.rows():
                yield self.BrowserLocalStorageRecord(
                    ts_created=None,
                    ts_last_modified=stat.st_mtime,
                    ts_last_accessed=None,
                    browser="ladybird",
                    host=row.get("storage_key"),
                    key=row.get("bottle_key"),
                    value=row.get("bottle_value"),
                    source=db_file,
                    _user=user_details.user,
                    _target=self.target,
                )
