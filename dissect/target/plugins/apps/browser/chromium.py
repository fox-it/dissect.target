from __future__ import annotations

import base64
import itertools
import json
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from dissect.cstruct import cstruct
from dissect.sql import sqlite3
from dissect.sql.exceptions import Error as SQLError
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

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.sql.sqlite3 import SQLite3

    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target

try:
    from Crypto.Cipher import AES, ChaCha20_Poly1305
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import unpad

    HAS_CRYPTO = True

except ImportError:
    HAS_CRYPTO = False


CHROMIUM_DOWNLOAD_RECORD_FIELDS = [
    ("uri", "tab_url"),
    ("uri", "tab_referrer_url"),
    ("string", "mime_type"),
]

# Resources:
# - Reversing ``PostProcessData`` in ``elevation_service.exe``
# - https://chromium.googlesource.com/chromium/src/+/master/chrome/elevation_service/elevator.cc
elevation_def = """
struct Envelope {
    uint32  program_len;
    char    program[program_len];
    uint32  ciphertext_len;
    char    ciphertext[ciphertext_len]; // basically until EOF
};
struct GoogleChromeCipher {
    uint8   flag;                       // 0x01 = AES GCM, 0x02 = ChaCha20 Poly1305
    char    iv[12];
    char    ciphertext[32];
    char    mac_tag[16];
};
"""
c_elevation = cstruct(endian="<").load(elevation_def)


class ChromiumMixin:
    """Mixin class with methods for Chromium-based browsers."""

    DIRS = ()

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
        self, filename: str, subdirs: list[str] | None = None
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
        seen = set()
        dirs = list(self.DIRS)
        if subdirs:
            dirs.extend([join(dir, subdir) for dir, subdir in itertools.product(self.DIRS, subdirs)])

        for user, cur_dir in self._build_userdirs(dirs):
            db_file = cur_dir.joinpath(filename)

            if db_file in seen:
                continue
            seen.add(db_file)

            try:
                yield user, db_file, sqlite3.SQLite3(db_file.open())
            except FileNotFoundError:
                self.target.log.warning("Could not find %s file: %s", filename, db_file)
            except SQLError as e:
                self.target.log.warning("Could not open %s file: %s", filename, db_file)
                self.target.log.debug("", exc_info=e)

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

    def history(self, browser_name: str | None = None) -> Iterator[BrowserHistoryRecord]:
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
            except SQLError as e:  # noqa: PERF203
                self.target.log.warning("Error processing history file: %s", db_file)
                self.target.log.debug("", exc_info=e)

    def cookies(self, browser_name: str | None = None) -> Iterator[BrowserCookieRecord]:
        """Return browser cookie records from supported Chromium-based browsers.

        Attempts to decrypt cookie values where possible.

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
            keys = {}

            if self.target.os == OperatingSystem.WINDOWS.value:
                try:
                    local_state_parent = db_file.parent.parent
                    if db_file.parent.name == "Network":
                        local_state_parent = local_state_parent.parent
                    local_state_path = local_state_parent.joinpath("Local State")

                    keys = self.decryption_keys(local_state_path, user.user.name)
                except ValueError as e:
                    self.target.log.warning("Failed to decrypt local state key in %s: %s", local_state_path, e)
                    self.target.log.debug("", exc_info=e)

            try:
                for cookie in db.table("cookies").rows():
                    cookie_value = cookie.value

                    if not cookie_value and keys and (encrypted_cookie := cookie.get("encrypted_value")):
                        try:
                            cookie_value = self.decrypt_value(user, keys, encrypted_cookie)
                        except (ValueError, UnicodeDecodeError) as e:
                            self.target.log.warning(
                                "Failed to decrypt cookie value for %s %s: %s", cookie.host_key, cookie.name, e
                            )

                        # Strip extra data
                        if cookie_value and encrypted_cookie[0:3] == b"v20":
                            cookie_value = cookie_value[32:]

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
                self.target.log.warning("Error processing cookie file %s: %s", db_file, e)
                self.target.log.debug("", exc_info=e)

    def downloads(self, browser_name: str | None = None) -> Iterator[BrowserDownloadRecord]:
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
            except SQLError as e:  # noqa: PERF203
                self.target.log.warning("Error processing history file: %s", db_file)
                self.target.log.debug("", exc_info=e)

    def extensions(self, browser_name: str | None = None) -> Iterator[BrowserExtensionRecord]:
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

                    for extension_id, extension_data in extensions.items():
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
                except (AttributeError, KeyError) as e:  # noqa: PERF203
                    self.target.log.warning("No browser extensions found in: %s", json_file)
                    self.target.log.debug("", exc_info=e)

    def passwords(self, browser_name: str | None = None) -> Iterator[BrowserPasswordRecord]:
        """Return browser password records from Chromium browsers.

        Chromium on Linux has ``basic``, ``gnome`` and ``kwallet`` methods for password storage:
            - ``basic`` ciphertext prefixed with ``v10`` and encrypted with hard coded parameters.
            - ``gnome`` and ``kwallet`` ciphertext prefixed with ``v11`` which is not implemented (yet).

        Chromium on Windows uses DPAPI user encryption with varying methods of encryption (``v10`` and ``v20``).

        The SHA1 hash of the user's password or the plaintext password is required to decrypt passwords
        when dealing with encrypted passwords created with Chromium v80 (February 2020) and newer (``v10``).

        Supports decrypting Windows App Bound Encryption passwords from Google Chrome and Microsoft Edge (``v20``).

        You can supply a SHA1 hash or plaintext password using the keychain (``-Kv`` or ``-K``).

        Resources:
            - https://chromium.googlesource.com/chromium/src/+/master/docs/linux/password_storage.md
            - https://chromium.googlesource.com/chromium/src/+/master/components/os_crypt/sync/os_crypt_linux.cc#40
        """

        for user, db_file, db in self._iter_db("Login Data"):
            keys = {}

            if self.target.os == OperatingSystem.WINDOWS.value:
                try:
                    local_state_path = db_file.parent.parent.joinpath("Local State")
                    keys = self.decryption_keys(local_state_path, user.user.name)
                except ValueError as e:
                    self.target.log.warning("Failed to decrypt local state key: %s", e)
                    self.target.log.debug("", exc_info=e)

            if not db.table("logins"):
                continue

            notes = {}
            if table := db.table("password_notes"):
                for row in table.rows():
                    notes[str(row.parent_id)] = row.value

            for row in db.table("logins").rows():
                encrypted_password: bytes = row.password_value
                decrypted_password = None

                # Attempt to decrypt password
                try:
                    decrypted_password = self.decrypt_value(user, keys, encrypted_password)
                except Exception as e:
                    self.target.log.warning("Failed to decrypt %r Chromium password: %s", encrypted_password[0:3], e)
                    self.target.log.debug("", exc_info=e)

                # Attempt to decrypt notes
                encrypted_notes = None
                decrypted_notes = None
                if encrypted_notes := notes.get(str(row.id)):
                    try:
                        decrypted_notes = self.decrypt_value(user, keys, encrypted_notes)
                    except Exception as e:
                        self.target.log.warning("Failed to decrypt %r Chromium note: %s", encrypted_notes[0:3], e)
                        self.target.log.debug("", exc_info=e)

                yield self.BrowserPasswordRecord(
                    ts_created=webkittimestamp(row.date_created),
                    ts_last_used=webkittimestamp(row.date_last_used),
                    ts_last_changed=webkittimestamp(row.date_password_modified or 0),
                    browser=browser_name,
                    id=row.id,
                    url=row.origin_url,
                    encrypted_username=None,
                    encrypted_password=row.password_value,
                    decrypted_username=row.username_value,
                    decrypted_password=decrypted_password,
                    encrypted_notes=encrypted_notes,
                    decrypted_notes=decrypted_notes,
                    source=db_file,
                    _target=self.target,
                    _user=user.user,
                )

    def decryption_keys(self, local_state_path: TargetPath, username: str) -> ChromiumKeys:
        """Return decrypted Chromium ``os_crypt.encrypted_key``and ``os_crypt.app_bound_encrypted_key`` values.

        Used by :meth:`ChromiumMixin.passwords` and :meth:`ChromiumMixin.cookies` for Windows targets.

        Resources:
            - https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html
            - https://github.com/chromium/chromium/tree/main/chrome/browser/os_crypt
            - https://github.com/chromium/chromium/tree/main/chrome/elevation_service
            - https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/os_crypt/sync/os_crypt_win.cc
        """
        keys = ChromiumKeys()

        if not local_state_path.exists():
            self.target.log.warning("File does not exist: %s", local_state_path)
            return keys

        try:
            local_state_conf = json.loads(local_state_path.read_text())
        except json.JSONDecodeError as e:
            self.target.log.warning("File does not contain valid JSON: %s in %s", e, local_state_path)
            return keys

        if "os_crypt" not in local_state_conf:
            self.target.log.warning(
                "File does not contain os_crypt, Chromium is likely older than v80: %s",
                local_state_path,
            )
            return keys

        if not self.target.has_function("dpapi"):
            self.target.log.warning(
                "Unable to decrypt Chromium os_crypt keys: DPAPI plugin is not compatible with target"
            )
            return keys

        if not HAS_CRYPTO:
            self.target.log.warning("Missing pycryptodome dependency for crypto operations")
            return keys

        # Windows Chromium version 80 > uses AES ``os_crypt.encrypted_key`` which can be decrypted with user DPAPI keys.
        # Reference: https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/os_crypt/sync/os_crypt_win.cc
        try:
            encrypted_key = base64.b64decode(local_state_conf["os_crypt"]["encrypted_key"])[5:]
            aes_key = self.target.dpapi.decrypt_user_blob(encrypted_key, username)
            self.target.log.info("Decrypted Chromium OS Crypt key: %r", aes_key)
            keys.os_crypt_key = aes_key

        except (KeyError, ValueError) as e:
            self.target.log.warning("Unable to decode Chromium os_crypt encrypted_key in %s: %s", local_state_path, e)
            self.target.log.debug("", exc_info=e)

        # Windows Google Chrome versions > 130 / 127 and Microsoft Edge >~ 130 use App Bound Protection
        # (``os_crypt.app_bound_encrypted_key``) which can be decrypted using System DPAPI -> User DPAPI
        # -> (optionally AES GCM if Google Chrome).
        # Reference: https://github.com/chromium/chromium/tree/main/chrome/elevation_service
        if b64_abe := local_state_conf["os_crypt"].get("app_bound_encrypted_key"):
            try:
                app_bound_encrypted_key = base64.b64decode(b64_abe)

                if (header := app_bound_encrypted_key[0:4]) != b"APPB":
                    self.target.log.warning(
                        "Encountered unexpected app bound encrypted key in %s: Invalid header %r",
                        local_state_path,
                        header,
                    )
                    return keys

                system_ciphertext = app_bound_encrypted_key[4:].strip(b"\x00")
                user_ciphertext = self.target.dpapi.decrypt_system_blob(system_ciphertext)
                plaintext = self.target.dpapi.decrypt_user_blob(user_ciphertext, username)

                s_plaintext = c_elevation.Envelope(plaintext)

                if s_plaintext.ciphertext_len == 0x20:
                    # Microsoft Edge just stores the 32 byte decryption key
                    self.target.log.info("Decrypted Microsoft Edge ABE key: %r", s_plaintext.ciphertext)
                    keys.app_bound_key = s_plaintext.ciphertext

                else:
                    # Google Chrome has encrypted the AES decryption key using either AES GCM or ChaCha20 Poly1305
                    # using a static key.
                    data = c_elevation.GoogleChromeCipher(s_plaintext.ciphertext)

                    if data.flag == 0x01:
                        key = bytes.fromhex("b31c6e241ac846728da9c1fac4936651cffb944d143ab816276bcc6da0284787")
                        cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=data.iv)

                    elif data.flag == 0x02:
                        key = bytes.fromhex("e98f37d7f4e1fa433d19304dc2258042090e2d1d7eea7670d41f738d08729660")
                        cipher = ChaCha20_Poly1305.new(key=key, nonce=data.iv)

                    else:
                        raise ValueError("Unsupported ElevationService key flag {data.flag!r}")  # noqa: TRY301

                    aes_key = cipher.decrypt_and_verify(data.ciphertext, data.mac_tag)

                    self.target.log.info("Decrypted Google Chrome ABE key: %r", aes_key)
                    keys.app_bound_key = aes_key

            except (KeyError, ValueError, EOFError) as e:
                self.target.log.warning(
                    "Unable to decode Chromium os_crypt app_bound_key in %s: %s", local_state_path, e
                )
                self.target.log.debug("", exc_info=e)

        return keys

    def decrypt_value(self, user: UserDetails, keys: ChromiumKeys, encrypted: bytes) -> bytes:
        """Attempt to decrypt the given encrypted bytes."""

        DECRYPT_MAP = {
            OperatingSystem.WINDOWS.value: {
                b"\x01\x00\x00": decrypt_dpapi,  # First three bytes of DPAPI blob signature.
                b"v10": decrypt_v10_windows,
                b"v20": decrypt_v20_windows,
            },
            OperatingSystem.UNIX.value: {
                b"v10": decrypt_v10_linux,
                b"v11": decrypt_v11_linux,
            },
            OperatingSystem.LINUX.value: {
                b"v10": decrypt_v10_linux,
                b"v11": decrypt_v11_linux,
            },
        }
        return DECRYPT_MAP.get(self.target.os, {}).get(encrypted[0:3], decrypt_unsupported)(
            self.target, user, keys, encrypted
        )


class ChromiumPlugin(ChromiumMixin, BrowserPlugin):
    """Chromium browser plugin."""

    __namespace__ = "chromium"

    DIRS = (
        # Linux
        ".config/chromium/Default",
        ".var/app/org.chromium.Chromium/config/chromium/Default",
        "snap/chromium/common/chromium/Default",
        # Windows
        "AppData/Local/Chromium/User Data/Default",
    )

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


@dataclass(eq=True)
class ChromiumKeys:
    """Contains decrypted Chromium-variant encryption keys."""

    os_crypt_key: bytes | None = None
    """Windows Chromium version 80 and up for ``b"v10"`` ciphertexts."""

    app_bound_key: bytes | None = None
    """Windows Google Chrome and Microsoft Edge versions 127 and up for ``b"v20"`` ciphertexts."""


def decrypt_v10_linux(
    target: Target, user: UserDetails, keys: ChromiumKeys, encrypted: bytes, *, hardcoded_key: str = "peanuts"
) -> bytes | None:
    """Decrypt a version 10 Linux ciphertext.

    ``v10`` ciphertexts are encrypted using a PBKDF2 key derivation of the static string ``peanuts`` or an empty string
    and salt ``saltysalt`` using AES CBC with an IV of ``0x20 * 16``. Padded using PKCS7.

    Args:
        ciphertext: The encrypted bytes.

    Returns:
        Decrypted password string.

    Resources:
        - https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/os_crypt/sync/os_crypt_linux.cc
    """

    if not HAS_CRYPTO:
        raise ValueError("Missing pycryptodome dependency for AES operation")

    ciphertext = encrypted[3:]

    salt = b"saltysalt"
    iv = b" " * 16

    key = PBKDF2(hardcoded_key, salt, 16, 1)
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)

    decrypted = cipher.decrypt(ciphertext)

    # No MAC so no way to verify if decryption worked other than check if unpadding works.
    # If unpadding failed, we try the legacy-legacy hardcoded empty key.
    try:
        return unpad(decrypted, 16)
    except ValueError:
        if hardcoded_key == "peanuts":
            return decrypt_v10_linux(target, user, keys, encrypted, hardcoded_key="")
        raise ValueError("Decrypting Chromium V10 secret failed")


def decrypt_v10_windows(target: Target, user: UserDetails, keys: ChromiumKeys, encrypted: bytes) -> bytes | None:
    """Decrypt a version 10 Windows ciphertext using key ``os_crypt_key``.

    ``v10`` variant 2 (Windows-specific) ciphertexts can be decrypted using a derived AES GCM
    key called ``os_crypt_key`` stored in an encrypted form in ``Local State`` files.

    The IV is prepended to the ciphertext as described in the structure definition below.

    References:

        .. code-block::

            struct chrome_pass {
                byte signature[3] = 'v10';
                byte iv[12];
                byte ciphertext[EOF];
            }

    Args:
        encrypted: Ciphertext bytes.
        key: The encryption key.

    Returns:
        Decrypted password string.
    """

    if not HAS_CRYPTO:
        raise ValueError("Missing pycryptodome dependency for AES operation")

    if not keys.os_crypt_key:
        raise ValueError("No OS Crypt key available for v10 version 2 decryption")

    iv = encrypted[3:15]
    ciphertext = encrypted[15:]
    cipher = AES.new(key=keys.os_crypt_key, mode=AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext[:-16]


def decrypt_v20_windows(target: Target, user: UserDetails, keys: ChromiumKeys, encrypted: bytes) -> bytes | None:
    """Decrypt a version 20 ciphertext using App Bound Encryption (``app_bound_key``).

    ``v20`` (Windows) ciphertexts can be decrypted using a derived AES GCM key called ``app_bound_key``
    stored in a double or triple encrypted form in ``Local State`` files.

    The IV and a MAC-tag for verification are stored in the ciphertext blob as can be observed in the
    structure definition below.

    References:

        .. code-block::

            struct chrome_pass {
                byte flag[3] = 'v20';
                byte iv[12];
                byte ciphertext[...];
                byte mac_tag[16];
            };

    Args:
        data: Encrypted ciphertext in structured format with flag, iv, ciphertext and tag.
        key: AES GCM key to decrypt data with.

    Returns:
        Decrypted plaintext.
    """
    if not HAS_CRYPTO:
        raise ValueError("Missing pycryptodome dependency for AES operation")

    if not keys.app_bound_key:
        raise ValueError("No ABE key available for v20 decryption")

    iv = encrypted[3 : 3 + 12]
    ciphertext = encrypted[3 + 12 : -16]
    mac_tag = encrypted[-16:]

    cipher = AES.new(key=keys.app_bound_key, mode=AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, mac_tag)


def decrypt_v11_linux(target: Target, user: UserDetails, keys: ChromiumKeys, encrypted: bytes) -> None:
    """Decrypt Linux GNOME or Kwallet encrypted passwords. Currently not implemented."""
    raise ValueError("Decrypting v11 Linux GNOME or Kwallet Chromium ciphertexts is not implemented.")


def decrypt_dpapi(target: Target, user: UserDetails, keys: ChromiumKeys, encrypted: bytes) -> bytes | None:
    """Decrypt a DPAPI user blob for Windows-based Chromium installs.

    Chromium on Windows prior to version 80 encrypts passwords using user DPAPI master keys.

    They can be decrypted directly by utilizing the DPAPI plugin.

    Resources:
        - https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/os_crypt/sync/os_crypt_win.cc
    """

    if not target.has_function("dpapi"):
        raise ValueError("Missing DPAPI plugin for DPAPI user secret decryption")

    if not encrypted.startswith(b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf"):
        raise ValueError("Provided blob does not look like a DPAPI Blob: {encrypted[:8]!r}")

    try:
        return target.dpapi.decrypt_user_blob(encrypted, user.user.name)

    except UnsupportedPluginError as e:
        target.log.warning("Target is missing required registry keys for DPAPI")
        target.log.debug("", exc_info=e)
    except ValueError as e:
        target.log.warning("Failed to decrypt DPAPI blob: %e", e)
        target.log.debug("", exc_info=e)


def decrypt_unsupported(target: Target, user: UserDetails, keys: ChromiumKeys, encrypted: bytes) -> None:
    raise ValueError(f"Unknown encrypted password found: {encrypted!r}")
