from dissect.sql import sqlite3
from dissect.sql.exceptions import Error as SQLError
from dissect.util.ts import webkittimestamp

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import (
    GENERIC_HISTORY_RECORD_FIELDS,
    try_idna,
)

EdgeBrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browser/edge/history", GENERIC_HISTORY_RECORD_FIELDS
)


class EdgePlugin(Plugin):
    """Edge browser plugin."""

    __namespace__ = "edge"

    DIRS = [
        # Windows
        "AppData/Local/Microsoft/Edge/User Data/Default",
        # Macos
        "Library/Application Support/Microsoft Edge/Default",
    ]

    def __init__(self, target):
        super().__init__(target)

        self.users_dirs = []
        for user_details in self.target.user_details.all_with_home():
            for d in self.DIRS:
                cur_dir = user_details.home_path.joinpath(d)
                if not cur_dir.exists():
                    continue
                self.users_dirs.append((user_details.user, cur_dir))

    def check_compatible(self):
        if not len(self.users_dirs):
            raise UnsupportedPluginError("No Edge directories found")

    def _iter_db(self, filename):
        for user, cur_dir in self.users_dirs:
            db_file = cur_dir.joinpath(filename)
            try:
                yield user, db_file, sqlite3.SQLite3(db_file.open())
            except FileNotFoundError:
                self.target.log.warning("Could not find %s file: %s", filename, db_file)
            except SQLError as e:
                self.target.log.warning("Could not open %s file: %s", filename, db_file, exc_info=e)

    @export(record=EdgeBrowserHistoryRecord)
    def history(self):
        """Return browser history records from Edge.

        Yields EdgeBrowserHistoryRecords with the following fields:
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
        """
        for user, db_file, db in self._iter_db("History"):
            try:
                urls = {row.id: row for row in db.table("urls").rows()}
                visits = {}

                for row in db.table("visits").rows():
                    visits[row.id] = row
                    url = urls[row.url]

                    if row.from_visit and row.from_visit in visits:
                        from_visit = visits[row.from_visit]
                        from_url = urls[from_visit.url]
                    else:
                        from_visit, from_url = None, None

                    yield EdgeBrowserHistoryRecord(
                        ts=webkittimestamp(row.visit_time),
                        browser="edge",
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
