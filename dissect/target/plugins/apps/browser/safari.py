from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.exception import Error as DBError
from dissect.database.sqlite3 import SQLite3
from dissect.util.ts import cocoatimestamp

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.browser.browser import (
    GENERIC_HISTORY_RECORD_FIELDS,
    BrowserPlugin,
    try_idna,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.plugins.general.users import UserDetails


class SafariPlugin(BrowserPlugin):
    """Safari browser plugin."""

    __namespace__ = "safari"

    DIRS = (
        # macOS
        "Library/Safari",
    )

    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/safari/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    def __init__(self, target):
        super().__init__(target)
        self.installs = list(self._find_installs())

    def _find_installs(self) -> Iterator[tuple[UserDetails, Path]]:
        for user_details in self.target.user_details.all_with_home():
            for directory in self.DIRS:
                install = user_details.home_path.joinpath(directory)
                if install.is_dir():
                    yield user_details, install

    def check_compatible(self) -> None:
        if not self.installs:
            raise UnsupportedPluginError("No Safari directories found on target")

    def _iter_db(self, filename: str) -> Iterator[tuple[UserDetails, Path, SQLite3]]:
        for user_details, install in self.installs:
            db_file = install.joinpath(filename)
            try:
                yield user_details, db_file, SQLite3(db_file)
            except FileNotFoundError:
                self.target.log.info("Could not find %s file: %s", filename, db_file)
            except DBError as e:
                self.target.log.warning("Could not open %s file: %s", filename, db_file)
                self.target.log.debug("", exc_info=e)

    @export(record=BrowserHistoryRecord)
    def history(self) -> Iterator[BrowserHistoryRecord]:
        """Return browser history records from Safari.

        Yields BrowserHistoryRecord with the following fields:

        .. code-block:: text

            ts (datetime): Visit timestamp.
            browser (string): The browser from which the records are generated from.
            id (varint): Record ID.
            url (uri): History URL.
            title (string): Page title.
            description (string): Page description.
            host (string): Hostname.
            visit_type (varint): Visit type.
            visit_count (varint): Amount of visits.
            hidden (boolean): Hidden value (synthesized visits).
            typed (boolean): Typed value.
            session (varint): Session value.
            from_visit (varint): Record ID of the redirect source visit.
            from_url (uri): URL of the redirect source visit.
            source (path): The source file of the history record.
        """
        for user_details, db_file, db in self._iter_db("History.db"):
            try:
                items = {row.id: row for row in db.table("history_items").rows()}
                visits = {}

                for row in db.table("history_visits").rows():
                    visits[row.id] = row
                    item = items[row.history_item]

                    from_visit = visits.get(row.redirect_source) if row.redirect_source else None
                    from_item = items.get(from_visit.history_item) if from_visit else None

                    yield self.BrowserHistoryRecord(
                        ts=cocoatimestamp(row.visit_time),
                        browser="safari",
                        id=row.id,
                        url=try_idna(item.url),
                        title=row.title,
                        description=None,
                        host=item.domain_expansion,
                        visit_type=None,
                        visit_count=item.visit_count,
                        hidden=bool(row.synthesized),
                        typed=None,
                        session=None,
                        from_visit=row.redirect_source or None,
                        from_url=try_idna(from_item.url) if from_item else None,
                        source=db_file,
                        _target=self.target,
                        _user=user_details.user if user_details else None,
                    )
            except DBError as e:  # noqa: PERF203
                self.target.log.warning("Error processing history file: %s", db_file)
                self.target.log.debug("", exc_info=e)
