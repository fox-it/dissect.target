from dissect.sql import sqlite3
from dissect.sql.exceptions import Error as SQLError
from dissect.util.ts import webkittimestamp

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import BrowserHistoryRecord, try_idna


class ChromePlugin(Plugin):
    """Chrome browser plugin."""

    __namespace__ = "chrome"

    DIRS = [
        "AppData/Local/Google/Chrome/User Data/Default",
        "AppData/Local/Google/Chrome/continuousUpdates/User Data/Default",
        "Local Settings/Application Data/Google/Chrome/User Data/Default",
        "AppData/local/Google/Chromium/User Data/Default",
        ".config/google-chrome/Default",
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
            raise UnsupportedPluginError("No Chrome directories found")

    @export(record=BrowserHistoryRecord)
    def history(self):
        """Return browser history records from Chrome.

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
            history_file = cur_dir.joinpath("History")
            try:
                db = sqlite3.SQLite3(history_file.open())
                for row in db.table("urls").rows():
                    yield BrowserHistoryRecord(
                        id=row.id,
                        browser="chrome",
                        url=try_idna(row.url),
                        title=row.title,
                        rev_host=None,
                        lastvisited=webkittimestamp(row.last_visit_time),
                        visit_count=row.visit_count,
                        hidden=row.hidden,
                        typed=None,
                        source=str(history_file),
                        _target=self.target,
                    )
            except FileNotFoundError:
                self.target.log.warning("Could not find history file: %s", history_file)
            except SQLError as e:
                self.target.log.warning("Could not open history file: %s", history_file, exc_info=e)
