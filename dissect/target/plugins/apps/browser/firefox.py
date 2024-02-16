import json
from pathlib import Path
from typing import Iterator

from dissect.sql import sqlite3
from dissect.sql.exceptions import Error as SQLError
from dissect.sql.sqlite3 import SQLite3
from dissect.util.ts import from_unix_ms, from_unix_us

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.apps.browser import firefox
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import arg, export
from dissect.target.plugins.apps.browser.browser import (
    GENERIC_COOKIE_FIELDS,
    GENERIC_DOWNLOAD_RECORD_FIELDS,
    GENERIC_HISTORY_RECORD_FIELDS,
    GENERIC_PASSWORD_RECORD_FIELDS,
    BrowserPlugin,
    try_idna,
)


class FirefoxPlugin(BrowserPlugin):
    """Firefox browser plugin."""

    __namespace__ = "firefox"

    DIRS = [
        # Windows
        "AppData/Roaming/Mozilla/Firefox/Profiles",
        "AppData/local/Mozilla/Firefox/Profiles",
        # Linux
        ".mozilla/firefox",
        "snap/firefox/common/.mozilla/firefox",
        ".var/app/org.mozilla.firefox/.mozilla/firefox",
        # macOS
        "Library/Application Support/Firefox",
    ]

    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/firefox/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    BrowserCookieRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/firefox/cookie", GENERIC_COOKIE_FIELDS
    )

    BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/firefox/download", GENERIC_DOWNLOAD_RECORD_FIELDS
    )

    BrowserPasswordRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/firefox/password", GENERIC_PASSWORD_RECORD_FIELDS
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

    def check_compatible(self) -> None:
        if not len(self.users_dirs):
            raise UnsupportedPluginError("No Firefox directories found")

    def _iter_profiles(self) -> Iterator[tuple[str, Path, Path]]:
        """Yield user directories."""
        for user, cur_dir in self.users_dirs:
            for profile_dir in cur_dir.iterdir():
                if not profile_dir.is_dir():
                    continue
                yield user, cur_dir, profile_dir

    def _iter_db(self, filename: str) -> Iterator[SQLite3]:
        """Yield opened history database files of all users.

        Args:
            filename: The filename of the database.

        Yields:
            Opened SQLite3 databases.
        """
        for user, cur_dir, profile_dir in self._iter_profiles():
            db_file = profile_dir.joinpath(filename)
            try:
                yield user, db_file, sqlite3.SQLite3(db_file.open())
            except FileNotFoundError:
                self.target.log.warning("Could not find %s file: %s", filename, db_file)
            except SQLError as e:
                self.target.log.warning("Could not open %s file: %s", filename, db_file, exc_info=e)

    @export(record=BrowserHistoryRecord)
    def history(self) -> Iterator[BrowserHistoryRecord]:
        """Return browser history records from Firefox.

        Yields BrowserHistoryRecord with the following fields:
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

                    yield self.BrowserHistoryRecord(
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
                        source=db_file,
                        _target=self.target,
                        _user=user,
                    )
            except SQLError as e:
                self.target.log.warning("Error processing history file: %s", db_file, exc_info=e)

    @export(record=BrowserCookieRecord)
    def cookies(self) -> Iterator[BrowserCookieRecord]:
        """Return browser cookie records from Firefox.

        Args:
            browser_name: The name of the browser as a string.

        Yields:
            Records with the following fields:
                ts_created (datetime): Cookie created timestamp.
                ts_last_accessed (datetime): Cookie last accessed timestamp.
                browser (string): The browser from which the records are generated from.
                name (string): The cookie name.
                value (string): The cookie value.
                host (string): Cookie host key.
                path (string): Cookie path.
                expiry (varint): Cookie expiry.
                is_secure (bool): Cookie secury flag.
                is_http_only (bool): Cookie http only flag.
                same_site (bool): Cookie same site flag.
        """
        for user, db_file, db in self._iter_db("cookies.sqlite"):
            try:
                for cookie in db.table("moz_cookies").rows():
                    yield self.BrowserCookieRecord(
                        ts_created=from_unix_us(cookie.creationTime),
                        ts_last_accessed=from_unix_us(cookie.lastAccessed),
                        browser="firefox",
                        name=cookie.name,
                        value=cookie.value,
                        host=cookie.host,
                        path=cookie.path,
                        expiry=cookie.expiry,
                        is_secure=bool(cookie.isSecure),
                        is_http_only=bool(cookie.isHttpOnly),
                        same_site=bool(cookie.sameSite),
                        source=db_file,
                        _user=user,
                    )
            except SQLError as e:
                self.target.log.warning("Error processing cookie file: %s", db_file, exc_info=e)

    @export(record=BrowserDownloadRecord)
    def downloads(self) -> Iterator[BrowserDownloadRecord]:
        """Return browser download records from Firefox.

        Yields BrowserDownloadRecord with the following fields:
            ts_start (datetime): Download start timestamp.
            ts_end (datetime): Download end timestamp.
            browser (string): The browser from which the records are generated from.
            id (string): Record ID.
            path (string): Download path.
            url (uri): Download URL.
            size (varint): Download file size.
            state (varint): Download state number.
            source: (path): The source file of the download record.
        """
        for user, db_file, db in self._iter_db("places.sqlite"):
            try:
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

                    metadata = annotation.get("downloads/metaData", {})

                    ts_end = None
                    size = None
                    state = None

                    content = metadata.get("content")
                    if content:
                        ts_end = metadata.get("content").get("endTime")
                        ts_end = from_unix_ms(ts_end) if ts_end else None

                        size = content.get("fileSize")
                        state = content.get("state")

                    dest_file_info = annotation.get("downloads/destinationFileURI", {})

                    if download_path := dest_file_info.get("content"):
                        download_path = self.target.fs.path(download_path)

                    place = places.get(place_id)
                    url = place.get("url")
                    url = try_idna(url) if url else None

                    yield self.BrowserDownloadRecord(
                        ts_start=dest_file_info.get("date_added"),
                        ts_end=ts_end,
                        browser="firefox",
                        id=annotation.get("id"),
                        path=download_path,
                        url=url,
                        size=size,
                        state=state,
                        source=db_file,
                        _target=self.target,
                        _user=user,
                    )
            except SQLError as e:
                self.target.log.warning("Error processing history file: %s", db_file, exc_info=e)

    @export(record=BrowserPasswordRecord)
    @arg(
        "--passwords",
        type=str,
        default="",
        help="Supply a firefox primary password (master password) to decrypt the internal password store.",
    )
    def passwords(self, firefox_primary_password="") -> Iterator[BrowserPasswordRecord]:
        """Return Firefox browser password records.

        Automatically decrypts passwords from Firefox 58 onwards (2018) if no primary password is set.
        Alternatively, you can supply a primary password through ``--passwords`` to access the Firefox password store.

        Resources:
            - https://github.com/lclevy/firepwd
        """

        for user, _, profile_dir in self._iter_profiles():
            login_file = profile_dir.joinpath("logins.json")
            key3_file = profile_dir.joinpath("key3.db")
            key4_file = profile_dir.joinpath("key4.db")

            if not login_file.exists():
                self.target.log.warning(
                    f"No 'logins.json' password file found for user {user} in directory {profile_dir}"
                )
                continue

            if key3_file.exists() and not key4_file.exists():
                self.target.log.warning(f"Unsupported file 'key3.db' found in {profile_dir}")
                continue

            if not key4_file.exists():
                self.target.log.warning(f"No 'key4.db' found in {profile_dir}")
                continue

            try:
                logins = json.load(login_file.open())

                for login in logins.get("logins", []):
                    decrypted_username, decrypted_password = firefox.decrypt(
                        login.get("encryptedUsername"),
                        login.get("encryptedPassword"),
                        key4_file,
                        firefox_primary_password,
                    )

                    yield self.BrowserPasswordRecord(
                        browser="firefox",
                        id=login.get("id"),
                        ts_created=login.get("timeCreated", 0) // 1000,
                        ts_last_used=login.get("timeLastUsed", 0) // 1000,
                        ts_last_changed=login.get("timePasswordChanged", 0) // 1000,
                        url=login.get("hostname"),
                        encrypted_username=login.get("encryptedUsername"),
                        encrypted_password=login.get("encryptedPassword"),
                        decrypted_username=decrypted_username,
                        decrypted_password=decrypted_password,
                        source=login_file,
                        _target=self.target,
                        _user=user,
                    )

            except FileNotFoundError:
                self.target.log.info(f"No password file found for user {user} in directory {profile_dir}.")
            except json.JSONDecodeError:
                self.target.log.warning(
                    f"logins.json file in directory {profile_dir} is malformed, consider inspecting the file manually."
                )
