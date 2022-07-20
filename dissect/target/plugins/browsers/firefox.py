from datetime import datetime

from dissect.sql import sqlite3
from dissect.sql.exceptions import Error as SQLError

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import BrowserHistoryRecord, try_idna


class FirefoxPlugin(Plugin):
    """Firefox browser plugin."""

    __namespace__ = "firefox"

    DIRS = [
        "AppData/Roaming/Mozilla/Firefox/Profiles",
        "AppData/local/Mozilla/Firefox/Profiles",
        ".mozilla/firefox",
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

    @export(record=BrowserHistoryRecord)
    def history(self):
        """Return browser history records from Firefox.

        Yields BrowserHistoryRecords with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            browser (string): The browser from which the records are generated from.
            id (string): Record ID.
            url (uri): History URL.
            title (string): Page title.
            rev_host (string): Reverse hostname.
            lastvisited (datetime): Last visited date and time.
            visit_count (varint): Amount of visits.
            hidden (string): Hidden value.
            typed (string): Typed value.
        """
        for _, cur_dir in self.users_dirs:
            for profile_dir in cur_dir.iterdir():
                if profile_dir.is_dir():
                    history_file = profile_dir.joinpath("places.sqlite")
                    try:
                        db = sqlite3.SQLite3(history_file.open())
                        for row in db.table("moz_places").rows():
                            lastvisited = (
                                row.last_visit_date
                                if not row.last_visit_date
                                else datetime.utcfromtimestamp(row.last_visit_date / 1000000.0)
                            )
                            yield BrowserHistoryRecord(
                                id=row.id,
                                browser="firefox",
                                url=try_idna(row.url),
                                title=row.title,
                                rev_host=try_idna(row.rev_host),
                                lastvisited=lastvisited,
                                visit_count=row.visit_count,
                                hidden=row.hidden,
                                typed=row.typed,
                                source=str(history_file),
                                _target=self.target,
                            )
                    except FileNotFoundError:
                        self.target.log.warning("Could not find history file: %s", history_file)
                    except SQLError as e:
                        self.target.log.warning("Could not open history file: %s", history_file, exc_info=e)
