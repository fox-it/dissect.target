from typing import Iterator

from dissect.sql import sqlite3
from dissect.sql.exceptions import Error as SQLError
from dissect.sql.sqlite3 import SQLite3
from dissect.util.ts import webkittimestamp
from flow.record import Record

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import (
    GENERIC_HISTORY_RECORD_FIELDS,
    try_idna,
)


class ChromiumMixin:
    """Mixin class with methods for Chromium-based browsers."""

    DIRS = []
    HISTORY_RECORD = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/chromium/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    def history(self, browser_name: str = None) -> Iterator[Record]:
        """Return browser history records from supported Chromium-based browsers.

        Args:
            browser_name: The name of the browser as a string.
        Yields:
            Records with the following fields:
                hostname (string): The target hostname.
                domain (string): The target domain.
                ts (datetime): Visit timestamp.
                browser (string): The browser from which the records are generated from.
                id (string): Record ID.
                url (uri): History URL.
                title (string): Page title.
                description (string): Page description.
                rev_host (string): Reverse hostname.
                visit_type (varint): Visit type.
                visit_count (varint): Amount of visits.
                hidden (string): Hidden value.
                typed (string): Typed value.
                session (varint): Session value.
                from_visit (varint): Record ID of the "from" visit.
                from_url (uri): URL of the "from" visit.
                source: (path): The source file of the history record.
        Raises:
            SQLError: If the history file could not be processed.
        """
        for user, db_file, db in self._iter_db("History"):
            try:
                urls = {row.id: row for row in db.table("urls").rows()}
                visits: dict = {}

                for row in db.table("visits").rows():
                    visits[row.id] = row
                    url = urls[row.url]

                    if row.from_visit and row.from_visit in visits:
                        from_visit = visits[row.from_visit]
                        from_url = urls[from_visit.url]
                    else:
                        from_visit, from_url = None, None

                    yield self.HISTORY_RECORD(
                        ts=webkittimestamp(row.visit_time),
                        browser=browser_name,
                        id=row.id,
                        url=try_idna(url.url),
                        title=url.title,
                        description=None,
                        rev_host=None,
                        visit_type=None,
                        visit_count=url.visit_count,
                        hidden=url.hidden,
                        typed=None,
                        session=None,
                        from_visit=row.from_visit or None,
                        from_url=try_idna(from_url.url) if from_url else None,
                        source=str(db_file),
                        _target=self.target,
                        _user=user,
                    )
            except SQLError as e:
                self.target.log.warning("Error processing history file: %s", db_file, exc_info=e)

    def _iter_db(self, filename: str) -> Iterator[SQLite3]:
        """Generate a connection to a sqlite history database files.

        Args:
            filename: The filename as string of the database where the history is stored.
        Yields:
            connection to db_file (SQLite3)
        Raises:
            FileNotFoundError: If the history file could not be found.
            SQLError: If the history file could not be opened.
        """

        for user, cur_dir in self._build_userdirs(self.DIRS):
            db_file = cur_dir.joinpath(filename)
            try:
                yield user, db_file, sqlite3.SQLite3(db_file.open())
            except FileNotFoundError:
                self.target.log.warning("Could not find %s file: %s", filename, db_file)
            except SQLError as e:
                self.target.log.warning("Could not open %s file: %s", filename, db_file, exc_info=e)

    def _build_userdirs(self, hist_paths: list[str]) -> list[tuple]:
        """Join the selected browser dirs with the user home path.

        Args:
            hist_paths: A list with browser paths as strings.

        Returns:
            list with tuples containing user and TargetPath object.
        """
        users_dirs: list[tuple] = []
        for user_details in self.target.user_details.all_with_home():
            for d in hist_paths:
                cur_dir: TargetPath = user_details.home_path.joinpath(d)
                if not cur_dir.exists():
                    continue
                users_dirs.append((user_details.user, cur_dir))
        return users_dirs

    def check_compatible(self) -> None:
        """Perform a compatibility check with the target.
        This function checks if any of the supported browser directories
        exists. Otherwise it should raise an ``UnsupportedPluginError``.
        Raises:
            UnsupportedPluginError: If the plugin could not be loaded.
        """
        if not len(self._build_userdirs(self.DIRS)):
            raise UnsupportedPluginError("No Chromium-based browser directories found")


class ChromiumPlugin(ChromiumMixin, Plugin):
    """Chromium browser plugin."""

    __namespace__ = "chromium"

    DIRS = [
        # Linux
        "snap/chromium/common/chromium/Default",
        # Windows
        "AppData/Local/Chromium/User Data/Default",
    ]

    @export(record=ChromiumMixin.HISTORY_RECORD)
    def history(self):
        """Return browser history records for Chromium browser."""
        yield from ChromiumMixin.history(self, "chromium")
