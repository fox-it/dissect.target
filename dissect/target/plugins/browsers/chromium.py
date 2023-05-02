import json
from collections import defaultdict
from typing import Iterator

from dissect.sql import sqlite3
from dissect.sql.exceptions import Error as SQLError
from dissect.sql.sqlite3 import SQLite3
from dissect.util.ts import webkittimestamp
from flow.record.fieldtypes import path

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import (
    GENERIC_DOWNLOAD_RECORD_FIELDS,
    GENERIC_EXTENSION_RECORD_FIELDS,
    GENERIC_HISTORY_RECORD_FIELDS,
    try_idna,
)
from dissect.target.plugins.general.users import UserDetails


class ChromiumMixin:
    """Mixin class with methods for Chromium-based browsers."""

    DIRS = []
    BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/chromium/download", GENERIC_DOWNLOAD_RECORD_FIELDS
    )
    BrowserExtensionRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/chromium/extension", GENERIC_EXTENSION_RECORD_FIELDS
    )
    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/chromium/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    def _build_userdirs(self, hist_paths: list[str]) -> list[tuple[UserDetails, TargetPath]]:
        """Join the selected browser dirs with the user home path.

        Args:
            hist_paths: A list with browser paths as strings.

        Returns:
            List of tuples containing user and history file path objects.
        """
        users_dirs: list[tuple] = []
        for user_details in self.target.user_details.all_with_home():
            for d in hist_paths:
                cur_dir: TargetPath = user_details.home_path.joinpath(d)
                cur_dir = cur_dir.resolve()
                if not cur_dir.exists() or (user_details.user, cur_dir) in users_dirs:
                    continue
                users_dirs.append((user_details.user, cur_dir))
        return users_dirs

    def _iter_db(self, filename: str) -> Iterator[SQLite3]:
        """Generate a connection to a sqlite history database file.

        Args:
            filename: The filename as string of the database where the history is stored.
        Yields:
            opened db_file (SQLite3)
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

    def _iter_json(self, filename: str) -> Iterator[tuple[str, TargetPath, dict]]:
        """Iterate over all JSON files in the user directories, yielding a tuple
        of user name, JSON file path, and the parsed JSON data.

        Args:
            filename (str): The name of the JSON file to search for in each
            user directory.

        Yields:
            A tuple containing the name of the user, the path to the JSON file, and the parsed JSON data.

        Raises:
            FileNotFoundError: If the json file could not be found.
        """
        for user, cur_dir in self._build_userdirs(self.DIRS):
            json_file = cur_dir.joinpath(filename)
            try:
                yield user, json_file, json.load(json_file.open())
            except FileNotFoundError:
                self.target.log.warning("Could not find %s file: %s", filename, json_file)

    def check_compatible(self) -> None:
        if not len(self._build_userdirs(self.DIRS)):
            raise UnsupportedPluginError("No Chromium-based browser directories found")

    def downloads(self, browser_name: str = None) -> Iterator[BrowserDownloadRecord]:
        """Return browser download records from supported Chromium-based browsers.

        Args:
            browser_name: The name of the browser as a string.
        Yields:
            Records with the following fields:
                hostname (string): The target hostname.
                domain (string): The target domain.
                ts_start (datetime): Download start timestamp.
                ts_end (datetime): Download end timestamp.
                browser (string): The browser from which the records are generated from.
                id (string): Record ID.
                path (string): Download path.
                url (uri): Download URL.
                size (varint): Download file size.
                state (varint): Download state number.
                source: (path): The source file of the download record.
        Raises:
            SQLError: If the history file could not be processed.
        """
        for user, db_file, db in self._iter_db("History"):
            try:
                download_chains = defaultdict(list)
                for row in db.table("downloads_url_chains"):
                    download_chains[row.id].append(row)

                for chain in download_chains.values():
                    chain.sort(key=lambda row: row.chain_index)

                for row in db.table("downloads").rows():
                    download_path = row.target_path
                    if download_path and self.target.os == "windows":
                        download_path = path.from_windows(download_path)
                    elif download_path:
                        download_path = path.from_posix(download_path)

                    url = None
                    download_chain = download_chains.get(row.id)

                    if download_chain:
                        url = download_chain[-1].url
                        url = try_idna(url)

                    yield self.BrowserDownloadRecord(
                        ts_start=webkittimestamp(row.start_time),
                        ts_end=webkittimestamp(row.end_time) if row.end_time else None,
                        browser=browser_name,
                        id=row.get("id"),
                        path=download_path,
                        url=url,
                        size=row.get("total_bytes"),
                        state=row.get("state"),
                        source=db_file,
                        _target=self.target,
                        _user=user,
                    )
            except SQLError as e:
                self.target.log.warning("Error processing history file: %s", db_file, exc_info=e)

    def extensions(self, browser_name: str = None) -> Iterator[BrowserExtensionRecord]:
        """Iterates over all installed extensions for a given browser.

        Parameters:
            - browser_name (str): Name of the browser to scan for extensions.

        Yields:
            - Iterator[BrowserExtensionRecord]: A generator that yields `BrowserExtensionRecord`
                with the following fields:
                    hostname (string): The target hostname.
                    domain (string): The target domain.
                    ts_install (datetime): Extension install timestamp.
                    ts_update (datetime): Extension update timestamp.
                    browser (string): The browser from which the records are generated.
                    id (string): Extension unique identifier.
                    name (string): Name of the extension.
                    short_name (string): Short name of the extension.
                    default_title (string): Default title of the extension.
                    description (string): Description of the extension.
                    version (string): Version of the extension.
                    ext_path (path): Relative path of the extension.
                    from_webstore (boolean): Extension from webstore.
                    permissions (string[]): Permissions of the extension.
                    manifest (varint): Version of the extensions' manifest.
                    source: (path): The source file of the download record.
        """
        ext_files = ["Preferences", "Secure Preferences"]
        for filename in ext_files:
            for user, json_file, content in self._iter_json(filename):
                try:
                    extensions = content.get("extensions").get("settings")

                    for extension_id in extensions.keys():
                        extension_data = extensions.get(extension_id)

                        ts_install = extension_data.get("first_install_time") or extension_data.get("install_time")
                        ts_update = extension_data.get("last_update_time")
                        if ts_install:
                            ts_install = webkittimestamp(ts_install)
                        if ts_update:
                            ts_update = webkittimestamp(ts_update)

                        ext_path = extension_data.get("path")
                        if ext_path and self.target.os == "windows":
                            ext_path = path.from_windows(ext_path)
                        elif ext_path:
                            ext_path = path.from_posix(ext_path)

                        manifest = extension_data.get("manifest")
                        if manifest:
                            name = manifest.get("name")
                            short_name = manifest.get("short_name")
                            description = manifest.get("description")
                            ext_version = manifest.get("version")
                            ext_permissions = manifest.get("permissions")
                            manifest_version = manifest.get("manifest_version")

                            if manifest.get("browser_action"):
                                default_title = manifest.get("browser_action").get("default_title")
                            else:
                                default_title = None

                        else:
                            name = None
                            short_name = None
                            default_title = None
                            description = None
                            ext_version = None
                            ext_permissions = None
                            manifest_version = None

                        yield self.BrowserExtensionRecord(
                            ts_install=ts_install,
                            ts_update=ts_update,
                            browser=browser_name,
                            id=extension_id,
                            name=name,
                            short_name=short_name,
                            default_title=default_title,
                            description=description,
                            version=ext_version,
                            ext_path=ext_path,
                            from_webstore=extensions.get(extension_id).get("from_webstore"),
                            permissions=ext_permissions,
                            manifest_version=manifest_version,
                            source=json_file,
                            _target=self.target,
                            _user=user,
                        )
                except (AttributeError, KeyError) as e:
                    self.target.log.info("No browser extensions found in: %s", json_file, exc_info=e)

    def history(self, browser_name: str = None) -> Iterator[BrowserHistoryRecord]:
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
                visits = {}

                for row in db.table("visits").rows():
                    visits[row.id] = row
                    url = urls[row.url]

                    if row.from_visit and row.from_visit in visits:
                        from_visit = visits[row.from_visit]
                        from_url = urls[from_visit.url]
                    else:
                        from_visit, from_url = None, None

                    yield self.BrowserHistoryRecord(
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
                        source=db_file,
                        _target=self.target,
                        _user=user,
                    )
            except SQLError as e:
                self.target.log.warning("Error processing history file: %s", db_file, exc_info=e)


class ChromiumPlugin(ChromiumMixin, Plugin):
    """Chromium browser plugin."""

    __namespace__ = "chromium"

    DIRS = [
        # Linux
        ".config/chromium/Default",
        ".var/app/org.chromium.Chromium/config/chromium/Default",
        "snap/chromium/common/chromium/Default",
        # Windows
        "AppData/Local/Chromium/User Data/Default",
    ]

    @export(record=ChromiumMixin.BrowserDownloadRecord)
    def downloads(self):
        """Return browser download records for Chromium browser."""
        yield from super().downloads("chromium")

    @export(record=ChromiumMixin.BrowserExtensionRecord)
    def extensions(self):
        """Return browser extension records for Chromium browser."""
        yield from super().extensions("chromium")

    @export(record=ChromiumMixin.BrowserHistoryRecord)
    def history(self):
        """Return browser history records for Chromium browser."""
        yield from super().history("chromium")
