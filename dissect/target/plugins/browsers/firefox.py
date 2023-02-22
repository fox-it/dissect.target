import json
from typing import Iterator

from dissect.sql import sqlite3
from dissect.sql.exceptions import Error as SQLError
from dissect.sql.sqlite3 import Row, SQLite3
from dissect.util.ts import from_unix_ms, from_unix_us
from flow.record.fieldtypes import datetime, path

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import (
    GENERIC_DOWNLOAD_RECORD_FIELDS,
    GENERIC_HISTORY_RECORD_FIELDS,
    try_idna,
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
    HISTORY_RECORD = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/firefox/history", GENERIC_HISTORY_RECORD_FIELDS
    )
    BROWSER_DOWNLOAD_RECORD = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/firefox/download", GENERIC_DOWNLOAD_RECORD_FIELDS
    )

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
        """Perform a compatibility check with the target.
        This function checks if any of the supported browser directories
        exists. Otherwise it should raise an ``UnsupportedPluginError``.

        Raises:
            UnsupportedPluginError: If the plugin could not be loaded.
        """
        if not len(self.users_dirs):
            raise UnsupportedPluginError("No Firefox directories found")

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

    @export(record=HISTORY_RECORD)
    def history(self) -> Iterator[HISTORY_RECORD]:
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
                    place: Row = places[row.place_id]

                    if row.from_visit and row.from_visit in visits:
                        from_visit = visits[row.from_visit]
                        from_place = places[from_visit.place_id]
                    else:
                        from_visit, from_place = None, None

                    yield self.HISTORY_RECORD(
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

    @export(record=BROWSER_DOWNLOAD_RECORD)
    def downloads(self) -> Iterator[BROWSER_DOWNLOAD_RECORD]:
        """Return browser download records from Firefox.

        Yields FirefoxBrowserHistoryRecord with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts_start (datetime): .
            ts_end (datetime): .
            browser (string): The browser from which the records are generated from.
            id (string): Record ID.
            path (string): .
            url (uri): History URL.
            size (string): .
            state (string): .
            source: (path): The source file of the history record.
        """
        for user, db_file, db in self._iter_db("places.sqlite"):
            try:
                # TODO: should implement proper indexing in SQLite at some point
                places = {row.id: row for row in db.table("moz_places").rows()}
                attributes = {row.id: row.name for row in db.table("moz_anno_attributes").rows()}
                annotations = {}

                for row in db.table("moz_annos"):
                    attribute_name = attributes.get(row.anno_attribute_id, row.anno_attribute_id)

                    if attribute_name == "downloads/metaData":
                        content = json.loads(row.content)
                    else:
                        content = row.content

                    if row.place_id not in annotations:
                        annotations[row.place_id] = {"id": row.id}

                    annotations[row.place_id][attribute_name] = {
                        "content": content,
                        "flags": row.flags,
                        "expiration": row.expiration,
                        "type": row.type,
                        "date_added": from_unix_us(row.dateAdded),
                        "last_modified": from_unix_us(row.lastModified),
                    }

                for place_id, annotation in annotations.items():
                    if "downloads/metaData" not in annotation:
                        continue

                    place: Row = places[place_id]
                    dest_file_info: dict = annotation["downloads/destinationFileURI"]
                    metadata: dict = annotation["downloads/metaData"]

                    ended: int = metadata["content"]["endTime"]
                    ended: datetime = from_unix_ms(ended) if ended else None

                    download_path: str = dest_file_info["content"]

                    if download_path and self.target.os == "windows":
                        download_path = path.from_windows(download_path)
                    elif download_path:
                        download_path = path(download_path)

                    yield self.BROWSER_DOWNLOAD_RECORD(
                        ts_start=dest_file_info["date_added"],
                        ts_end=ended,
                        browser="firefox",
                        id=annotation["id"],
                        path=download_path,
                        url=try_idna(place.url),
                        size=metadata["content"]["fileSize"],
                        state=metadata["content"]["state"],
                        source=str(db_file),
                        _target=self.target,
                    )
            except SQLError as e:
                self.target.log.warning("Error processing history file: %s", db_file, exc_info=e)
