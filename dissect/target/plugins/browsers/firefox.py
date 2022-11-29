from dissect.sql import sqlite3
from dissect.sql.exceptions import Error as SQLError
from dissect.util.ts import from_unix_us

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import (
    GENERIC_HISTORY_RECORD_FIELDS,
    try_idna,
)

FirefoxBrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browser/firefox/history", GENERIC_HISTORY_RECORD_FIELDS
)


class FirefoxPlugin(Plugin):
    """Firefox browser plugin."""

    __namespace__ = "firefox"

    DIRS = [
        "AppData/Roaming/Mozilla/Firefox/Profiles",
        "AppData/local/Mozilla/Firefox/Profiles",
        ".mozilla/firefox",
        "snap/firefox/common/.mozilla/firefox",
    ]

    def __init__(self, target):
        super().__init__(target)

        self.users_dirs = []
        for user_details in self.target.user_details.all_with_home():
            for directory in self.DIRS:
                cur_dir = user_details.home_path.joinpath(directory)
                if not cur_dir.exists():
                    continue
                self.users_dirs.append((user_details.user, cur_dir))

    def check_compatible(self):
        if not len(self.users_dirs):
            raise UnsupportedPluginError("No Firefox directories found")

    def _iter_db(self, filename):
        for user, cur_dir in self.users_dirs:
            for profile_dir in cur_dir.iterdir():
                if profile_dir.is_dir():
                    db_file = profile_dir.joinpath(filename)
                    try:
                        yield user, db_file, sqlite3.SQLite3(db_file.open())
                    except FileNotFoundError:
                        self.target.log.warning("Could not find %s file: %s", filename, db_file)
                    except SQLError as e:
                        self.target.log.warning("Could not open %s file: %s", filename, db_file, exc_info=e)

    @export(record=FirefoxBrowserHistoryRecord)
    def history(self):
        """Return browser history records from Firefox.

        Yields FirefoxBrowserHistoryRecord with the following fields:
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
        for user, db_file, db in self._iter_db("places.sqlite"):
            try:
                places = {row.id: row for row in db.table("moz_places").rows()}
                visits = {}

                for row in db.table("moz_historyvisits").rows():
                    visits[row.id] = row
                    place = places[row.place_id]

                    if row.from_visit and row.from_visit in visits:
                        from_visit = visits[row.from_visit]
                        from_place = places[from_visit.place_id]
                    else:
                        from_visit, from_place = None, None

                    yield FirefoxBrowserHistoryRecord(
                        ts=from_unix_us(row.visit_date),
                        browser="firefox",
                        id=row.id,
                        url=try_idna(place.url),
                        title=place.title,
                        description=place.description,
                        rev_host=try_idna(place.rev_shot),
                        visit_type=row.visit_type,
                        visit_count=place.visit_count,
                        hidden=place.hidden,
                        typed=place.typed,
                        session=row.session,
                        from_visit=row.from_visit or None,
                        from_url=try_idna(from_place.url) if from_place else None,
                        source=str(db_file),
                        _target=self.target,
                        _user=user,
                    )
            except SQLError as e:
                self.target.log.warning("Error processing history file: %s", db_file, exc_info=e)
