import base64
import itertools
import json
from collections import defaultdict
from typing import Iterator, Optional

from dissect.sql import sqlite3
from dissect.sql.exceptions import Error as SQLError
from dissect.sql.sqlite3 import SQLite3
from dissect.util.ts import webkittimestamp

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath, join
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.apps.browser.browser import (
    GENERIC_COOKIE_FIELDS,
    GENERIC_DOWNLOAD_RECORD_FIELDS,
    GENERIC_EXTENSION_RECORD_FIELDS,
    GENERIC_HISTORY_RECORD_FIELDS,
    GENERIC_PASSWORD_RECORD_FIELDS,
    BrowserPlugin,
    try_idna,
)
from dissect.target.plugins.general.users import UserDetails

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2

    HAS_CRYPTO = True

except ImportError:
    HAS_CRYPTO = False


CHROMIUM_DOWNLOAD_RECORD_FIELDS = [
    ("uri", "tab_url"),
    ("uri", "tab_referrer_url"),
    ("string", "mime_type"),
]


class ChromiumMixin:
    """Mixin class with methods for Chromium-based browsers."""

    DIRS = []

    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/chromium/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    BrowserCookieRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/chromium/cookie", GENERIC_COOKIE_FIELDS
    )

    BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/chromium/download", GENERIC_DOWNLOAD_RECORD_FIELDS + CHROMIUM_DOWNLOAD_RECORD_FIELDS
    )

    BrowserExtensionRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/chromium/extension", GENERIC_EXTENSION_RECORD_FIELDS
    )

    BrowserPasswordRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/chromium/password", GENERIC_PASSWORD_RECORD_FIELDS
    )

    def _build_userdirs(self, hist_paths: list[str]) -> list[tuple[UserDetails, TargetPath]]:
        """Join the selected browser dirs with the user home path.

        Args:
            hist_paths: A list with browser paths as strings.

        Returns:
            List of tuples containing user and file path objects.
        """
        users_dirs: list[tuple] = []
        for user_details in self.target.user_details.all_with_home():
            for d in hist_paths:
                home_dir: TargetPath = user_details.home_path
                for cur_dir in home_dir.glob(d):
                    cur_dir = cur_dir.resolve()
                    if not cur_dir.exists() or (user_details.user, cur_dir) in users_dirs:
                        continue
                    users_dirs.append((user_details, cur_dir))
        return users_dirs

    def _iter_db(
        self, filename: str, subdirs: Optional[list[str]] = None
    ) -> Iterator[tuple[UserDetails, TargetPath, SQLite3]]:
        """Generate a connection to a sqlite database file.

        Args:
            filename: The filename as string of the database where the data is stored.
            subdirs: Subdirectories to also try for every configured directory.

        Yields:
            opened db_file (SQLite3)

        Raises:
            FileNotFoundError: If the history file could not be found.
            SQLError: If the history file could not be opened.
        """

        dirs = self.DIRS
        if subdirs:
            dirs.extend([join(dir, subdir) for dir, subdir in itertools.product(self.DIRS, subdirs)])

        for user, cur_dir in self._build_userdirs(dirs):
            db_file = cur_dir.joinpath(filename)
            try:
                yield user, db_file, sqlite3.SQLite3(db_file.open())
            except FileNotFoundError:
                self.target.log.warning("Could not find %s file: %s", filename, db_file)
            except SQLError as e:
                self.target.log.warning("Could not open %s file: %s", filename, db_file, exc_info=e)

    def _iter_json(self, filename: str) -> Iterator[tuple[UserDetails, TargetPath, dict]]:
        """Iterate over all JSON files in the user directories, yielding a tuple
        of username, JSON file path, and the parsed JSON data.

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
        if not self._build_userdirs(self.DIRS):
            raise UnsupportedPluginError("No Chromium-based browser directories found")

    def history(self, browser_name: Optional[str] = None) -> Iterator[BrowserHistoryRecord]:
        """Return browser history records from supported Chromium-based browsers.

        Args:
            browser_name: The name of the browser as a string.

        Yields:

        .. code-block:: text

            Records with the following fields:
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
                        _user=user.user,
                    )
            except SQLError as e:
                self.target.log.warning("Error processing history file: %s", db_file, exc_info=e)

    def cookies(self, browser_name: Optional[str] = None) -> Iterator[BrowserCookieRecord]:
        """Return browser cookie records from supported Chromium-based browsers.

        Args:
            browser_name: The name of the browser as a string.

        Yields:

        .. code-block:: text

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
        for user, db_file, db in self._iter_db("Cookies", subdirs=["Network"]):
            decrypted_key = None

            if self.target.os == OperatingSystem.WINDOWS.value:
                try:
                    local_state_parent = db_file.parent.parent
                    if db_file.parent.name == "Network":
                        local_state_parent = local_state_parent.parent
                    local_state_path = local_state_parent.joinpath("Local State")

                    decrypted_key = self._get_local_state_key(local_state_path, user.user.name)
                except ValueError:
                    self.target.log.warning("Failed to decrypt local state key")

            try:
                for cookie in db.table("cookies").rows():
                    cookie_value = cookie.value

                    if (
                        not cookie_value
                        and decrypted_key
                        and (enc_value := cookie.get("encrypted_value"))
                        and enc_value.startswith(b"v10")
                    ):
                        try:
                            if self.target.os == OperatingSystem.LINUX.value:
                                cookie_value = decrypt_v10(enc_value)
                            elif self.target.os == OperatingSystem.WINDOWS.value:
                                cookie_value = decrypt_v10_2(enc_value, decrypted_key)
                        except (ValueError, UnicodeDecodeError):
                            pass

                    if not cookie_value:
                        self.target.log.warning(
                            "Failed to decrypt cookie value for %s %s", cookie.host_key, cookie.name
                        )

                    yield self.BrowserCookieRecord(
                        ts_created=webkittimestamp(cookie.creation_utc),
                        ts_last_accessed=webkittimestamp(cookie.last_access_utc),
                        browser=browser_name,
                        name=cookie.name,
                        value=cookie_value,
                        host=cookie.host_key,
                        path=cookie.path,
                        expiry=int(cookie.has_expires),
                        is_secure=bool(cookie.is_secure),
                        is_http_only=bool(cookie.is_httponly),
                        same_site=bool(cookie.samesite),
                        source=db_file,
                        _target=self.target,
                        _user=user.user,
                    )
            except SQLError as e:
                self.target.log.warning("Error processing cookie file: %s", db_file, exc_info=e)

    def downloads(self, browser_name: Optional[str] = None) -> Iterator[BrowserDownloadRecord]:
        """Return browser download records from supported Chromium-based browsers.

        Args:
            browser_name: The name of the browser as a string.

        Yields:

        .. code-block:: text

            Records with the following fields:
                ts_start (datetime): Download start timestamp.
                ts_end (datetime): Download end timestamp.
                browser (string): The browser from which the records are generated from.
                id (string): Record ID.
                path (string): Download path.
                url (uri): Download URL.
                tab_url (string): Tab URL.
                tab_referrer_url (string): Referrer URL.
                size (varint): Download file size.
                mime_type (string): MIME type.
                state (varint): Download state number.
                source: (path): The source file of the download record.
        """
        for user, db_file, db in self._iter_db("History"):
            try:
                download_chains = defaultdict(list)
                for row in db.table("downloads_url_chains"):
                    download_chains[row.id].append(row)

                for chain in download_chains.values():
                    chain.sort(key=lambda row: row.chain_index)

                for row in db.table("downloads").rows():
                    if download_path := row.target_path:
                        download_path = self.target.fs.path(download_path)

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
                        tab_url=try_idna(row.get("tab_url")),
                        tab_referrer_url=try_idna(row.get("tab_referrer_url")),
                        path=download_path,
                        url=url,
                        size=row.get("total_bytes"),
                        mime_type=row.get("mime_type"),
                        state=row.get("state"),
                        source=db_file,
                        _target=self.target,
                        _user=user.user,
                    )
            except SQLError as e:
                self.target.log.warning("Error processing history file: %s", db_file, exc_info=e)

    def extensions(self, browser_name: Optional[str] = None) -> Iterator[BrowserExtensionRecord]:
        """Iterates over all installed extensions for a given browser.

        Args:
            browser_name (str): Name of the browser to scan for extensions.

        Yields:

        .. code-block:: text

            Records with the following fields:
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

                        if ext_path := extension_data.get("path"):
                            ext_path = self.target.fs.path(ext_path)

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
                            _user=user.user,
                        )
                except (AttributeError, KeyError) as e:
                    self.target.log.info("No browser extensions found in: %s", json_file, exc_info=e)

    def _get_local_state_key(self, local_state_path: TargetPath, username: str) -> Optional[bytes]:
        """Get the Chromium ``os_crypt`` ``encrypted_key`` and decrypt it using DPAPI."""

        if not local_state_path.exists():
            self.target.log.warning("File %s does not exist.", local_state_path)
            return None

        try:
            local_state_conf = json.loads(local_state_path.read_text())
        except json.JSONDecodeError:
            self.target.log.warning("File %s does not contain valid JSON.", local_state_path)
            return None

        if "os_crypt" not in local_state_conf:
            self.target.log.warning(
                "File %s does not contain os_crypt, Chrome is likely older than v80.", local_state_path
            )
            return None

        encrypted_key = base64.b64decode(local_state_conf["os_crypt"]["encrypted_key"])[5:]
        decrypted_key = self.target.dpapi.decrypt_user_blob(encrypted_key, username)
        return decrypted_key

    def passwords(self, browser_name: str = None) -> Iterator[BrowserPasswordRecord]:
        """Return browser password records from Chromium browsers.

        Chromium on Linux has ``basic``, ``gnome`` and ``kwallet`` methods for password storage:
            - ``basic`` ciphertext prefixed with ``v10`` and encrypted with hard coded parameters.
            - ``gnome`` and ``kwallet`` ciphertext prefixed with ``v11`` which is not implemented (yet).

        Chromium on Windows uses DPAPI user encryption.

        The SHA1 hash of the user's password or the plaintext password is required to decrypt passwords
        when dealing with encrypted passwords created with Chromium v80 (February 2020) and newer.

        You can supply a SHA1 hash or plaintext password using the keychain.

        Resources:
            - https://chromium.googlesource.com/chromium/src/+/master/docs/linux/password_storage.md
            - https://chromium.googlesource.com/chromium/src/+/master/components/os_crypt/sync/os_crypt_linux.cc#40
        """

        for user, db_file, db in self._iter_db("Login Data"):
            decrypted_key = None

            if self.target.os == OperatingSystem.WINDOWS.value:
                try:
                    local_state_path = db_file.parent.parent.joinpath("Local State")
                    decrypted_key = self._get_local_state_key(local_state_path, user.user.name)
                except ValueError:
                    self.target.log.warning("Failed to decrypt local state key")

            for row in db.table("logins").rows():
                encrypted_password: bytes = row.password_value
                decrypted_password = None

                # 1. Windows DPAPI encrypted password. Chrome > 80
                #    For passwords saved after Chromium v80, we have to use DPAPI to decrypt the AES key
                #    stored by Chromium to encrypt and decrypt passwords.
                if self.target.os == OperatingSystem.WINDOWS.value and encrypted_password.startswith(b"v10"):
                    if not decrypted_key:
                        self.target.log.warning("Cannot decrypt password, no decrypted_key could be calculated")

                    else:
                        try:
                            decrypted_password = decrypt_v10_2(encrypted_password, decrypted_key)
                        except Exception as e:
                            self.target.log.warning("Failed to decrypt AES Chromium password")
                            self.target.log.debug("", exc_info=e)

                # 2. Windows DPAPI encrypted password. Chrome < 80
                #    For passwords saved before Chromium v80, we use DPAPI directly for each entry.
                elif self.target.os == OperatingSystem.WINDOWS.value and encrypted_password.startswith(
                    b"\x01\x00\x00\x00"
                ):
                    try:
                        decrypted_password = self.target.dpapi.decrypt_blob(encrypted_password)
                    except ValueError as e:
                        self.target.log.warning("Failed to decrypt DPAPI Chromium password")
                        self.target.log.debug("", exc_info=e)
                    except UnsupportedPluginError as e:
                        self.target.log.warning("Target is missing required registry keys for DPAPI")
                        self.target.log.debug("", exc_info=e)

                # 3. Linux 'basic' v10 encrypted password.
                elif self.target.os != OperatingSystem.WINDOWS.value and encrypted_password.startswith(b"v10"):
                    try:
                        decrypted_password = decrypt_v10(encrypted_password)
                    except Exception as e:
                        self.target.log.warning("Failed to decrypt AES Chromium password")
                        self.target.log.debug("", exc_info=e)

                # 4. Linux 'gnome' or 'kwallet' encrypted password.
                elif self.target.os != OperatingSystem.WINDOWS.value and encrypted_password.startswith(b"v11"):
                    self.target.log.warning(
                        "Unable to decrypt %s password in '%s': unsupported format", browser_name, db_file
                    )

                # 5. Unsupported.
                else:
                    prefix = encrypted_password[:10]
                    self.target.log.warning(
                        "Unsupported %s encrypted password found in '%s' with prefix '%s'",
                        browser_name,
                        db_file,
                        prefix,
                    )

                yield self.BrowserPasswordRecord(
                    ts_created=webkittimestamp(row.date_created),
                    ts_last_used=webkittimestamp(row.date_last_used),
                    ts_last_changed=webkittimestamp(row.date_password_modified or 0),
                    browser=browser_name,
                    id=row.id,
                    url=row.origin_url,
                    encrypted_username=None,
                    encrypted_password=base64.b64encode(row.password_value),
                    decrypted_username=row.username_value,
                    decrypted_password=decrypted_password,
                    source=db_file,
                    _target=self.target,
                    _user=user.user,
                )


class ChromiumPlugin(ChromiumMixin, BrowserPlugin):
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

    @export(record=ChromiumMixin.BrowserHistoryRecord)
    def history(self) -> Iterator[ChromiumMixin.BrowserHistoryRecord]:
        """Return browser history records for Chromium browser."""
        yield from super().history("chromium")

    @export(record=ChromiumMixin.BrowserCookieRecord)
    def cookies(self) -> Iterator[ChromiumMixin.BrowserCookieRecord]:
        """Return browser cookie records for Chromium browser."""
        yield from super().cookies("chromium")

    @export(record=ChromiumMixin.BrowserDownloadRecord)
    def downloads(self) -> Iterator[ChromiumMixin.BrowserDownloadRecord]:
        """Return browser download records for Chromium browser."""
        yield from super().downloads("chromium")

    @export(record=ChromiumMixin.BrowserExtensionRecord)
    def extensions(self) -> Iterator[ChromiumMixin.BrowserExtensionRecord]:
        """Return browser extension records for Chromium browser."""
        yield from super().extensions("chromium")

    @export(record=ChromiumMixin.BrowserPasswordRecord)
    def passwords(self) -> Iterator[ChromiumMixin.BrowserPasswordRecord]:
        """Return browser password records for Chromium browser."""
        yield from super().passwords("chromium")


def remove_padding(decrypted: bytes) -> bytes:
    number_of_padding_bytes = decrypted[-1]
    return decrypted[:-number_of_padding_bytes]


def decrypt_v10(encrypted_password: bytes) -> str:
    """Decrypt a version 10 encrypted password.

    Args:
        encrypted_password: The encrypted password bytes.

    Returns:
        Decrypted password string.
    """

    if not HAS_CRYPTO:
        raise ValueError("Missing pycryptodome dependency for AES operation")

    encrypted_password = encrypted_password[3:]

    salt = b"saltysalt"
    iv = b" " * 16
    pbkdf_password = "peanuts"

    key = PBKDF2(pbkdf_password, salt, 16, 1)
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)

    decrypted = cipher.decrypt(encrypted_password)
    return remove_padding(decrypted).decode()


def decrypt_v10_2(encrypted_password: bytes, key: bytes) -> str:
    """Decrypt a version 10 type 2 password.

    References:

        .. code-block::

            struct chrome_pass {
                byte signature[3] = 'v10';
                byte iv[12];
                byte ciphertext[EOF];
            }

    Args:
        encrypted_password: The encrypted password bytes.
        key: The encryption key.

    Returns:
        Decrypted password string.
    """

    if not HAS_CRYPTO:
        raise ValueError("Missing pycryptodome dependency for AES operation")

    iv = encrypted_password[3:15]
    ciphertext = encrypted_password[15:]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext[:-16].decode(errors="backslashreplace")
