from __future__ import annotations

import base64
import itertools
import json
from base64 import b64decode
from hashlib import pbkdf2_hmac, sha1
from itertools import chain
from typing import TYPE_CHECKING

from dissect.database.exception import Error as DBError
from dissect.database.sqlite3 import SQLite3
from dissect.util.ts import from_unix_ms, from_unix_us

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.logging import get_logger
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
    from pathlib import Path

    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target

try:
    from asn1crypto import algos, core

    HAS_ASN1 = True

except ImportError:
    HAS_ASN1 = False


try:
    from Crypto.Cipher import AES, DES3
    from Crypto.Util.Padding import unpad

    HAS_CRYPTO = True

except ImportError:
    HAS_CRYPTO = False

FIREFOX_EXTENSION_RECORD_FIELDS = [
    ("uri", "source_uri"),
    ("string[]", "optional_permissions"),
]


log = get_logger(__name__)


class FirefoxPlugin(BrowserPlugin):
    """Firefox browser plugin."""

    __namespace__ = "firefox"

    USER_DIRS = (
        # Windows
        "AppData/Roaming/Mozilla/Firefox/Profiles",
        "AppData/local/Mozilla/Firefox/Profiles",
        # Linux (146 and before)
        ".mozilla/firefox",
        "snap/firefox/common/.mozilla/firefox",
        ".var/app/org.mozilla.firefox/.mozilla/firefox",
        # Linux (147 and newer) uses XDG_CONFIG_HOME by default
        ".config/mozilla/firefox",
        "snap/firefox/common/.config/mozilla/firefox",
        ".var/app/org.mozilla.firefox/.config/mozilla/firefox",
        # macOS
        "Library/Application Support/Firefox",
    )

    SYSTEM_DIRS = (
        # Android Oculus VR
        "/data/data/org.mozilla.vrbrowser/files/mozilla",
    )

    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/firefox/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    BrowserCookieRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/firefox/cookie", GENERIC_COOKIE_FIELDS
    )

    BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/firefox/download", GENERIC_DOWNLOAD_RECORD_FIELDS
    )

    BrowserExtensionRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/firefox/extension",
        GENERIC_EXTENSION_RECORD_FIELDS + FIREFOX_EXTENSION_RECORD_FIELDS,
    )

    BrowserPasswordRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/firefox/password", GENERIC_PASSWORD_RECORD_FIELDS
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.installs = list(self.find_installs())

    def find_installs(self) -> Iterator[tuple[UserDetails | None, Path]]:
        """Find Firefox install directories on the target."""

        for user_details in self.target.user_details.all_with_home():
            for directory in self.USER_DIRS:
                if (install := user_details.home_path.joinpath(directory)).is_dir():
                    yield user_details, install

        for directory in self.SYSTEM_DIRS:
            if (install := self.target.fs.path(directory)).is_dir():
                yield None, install

    def check_compatible(self) -> None:
        if not len(self.installs):
            raise UnsupportedPluginError("No Firefox directories found on target")

    def _iter_profiles(self) -> Iterator[tuple[UserDetails | None, Path, Path]]:
        """Yield user directories by iterating over found Firefox install directories.

        Currently does not parse ``$INSTALL/profiles.ini`` file.
        """

        seen = set()

        for user_details, install in self.installs:
            for child in install.iterdir():
                # Profile dirs have a dot in their name
                if not child.is_dir() or "." not in child.name:
                    continue

                # Prevent duplicates
                if child in seen:
                    continue
                seen.add(child)

                yield user_details, install, child

    def _iter_db(self, filename: str) -> Iterator[tuple[UserDetails | None, Path, SQLite3]]:
        """Yield opened history database files of all users.

        Args:
            filename: The filename of the database.

        Yields:
            Opened SQLite3 databases.
        """

        iter_system = ((None, system_dir, None) for user, system_dir in self.installs if user is None)

        for user_details, install, profile_dir in chain(iter_system, self._iter_profiles()):
            if user_details is None and profile_dir is None:
                db_file = install.parent.joinpath(filename)
                # On some Android variants, some files may exist in the base directory (places.sqlite) but others
                # in a nested profile directory (cookies.sqlite)
                # /data/data/org.mozilla.vrbrowser/files/places.sqlite
                # /data/data/org.mozilla.vrbrowser/files/mozilla/xxxxxx.default/cookies.sqlite
                if not db_file.exists():
                    continue
            else:
                db_file = profile_dir.joinpath(filename)

            try:
                yield user_details, db_file, SQLite3(db_file)
            except FileNotFoundError:
                self.target.log.info("Could not find %s file: %s", filename, db_file)
            except DBError as e:
                self.target.log.warning("Could not open %s file: %s", filename, db_file)
                self.target.log.debug("", exc_info=e)

    @export(record=BrowserHistoryRecord)
    def history(self) -> Iterator[BrowserHistoryRecord]:
        """Return browser history records from Firefox.

        Yields BrowserHistoryRecord with the following fields:

        .. code-block:: text

            ts (datetime): Visit timestamp.
            browser (string): The browser from which the records are generated from.
            id (string): Record ID.
            url (uri): History URL.
            title (string): Page title.
            description (string): Page description.
            host (string): Hostname.
            visit_type (varint): Visit type.
            visit_count (varint): Amount of visits.
            hidden (string): Hidden value.
            typed (boolean): Typed value.
            session (varint): Session value.
            from_visit (varint): Record ID of the "from" visit.
            from_url (uri): URL of the "from" visit.
            source: (path): The source file of the history record.
        """
        from_timestamp = from_unix_ms if self.target.os == OperatingSystem.ANDROID else from_unix_us

        for user_details, db_file, db in self._iter_db("places.sqlite"):
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
                        ts=from_timestamp(row.visit_date),
                        browser="firefox",
                        id=row.id,
                        url=try_idna(place.url),
                        title=place.title,
                        description=place.description,
                        host="".join(list(reversed(try_idna(place.rev_host).decode()))).lstrip(".")
                        if place.rev_host
                        else None,
                        visit_type=row.visit_type,
                        visit_count=place.visit_count,
                        hidden=place.hidden,
                        typed=place.typed,
                        session=row.session,
                        from_visit=row.from_visit or None,
                        from_url=try_idna(from_place.url) if from_place else None,
                        source=db_file,
                        _target=self.target,
                        _user=user_details.user if user_details else None,
                    )
            except DBError as e:  # noqa: PERF203
                self.target.log.warning("Error processing history file: %s", db_file)
                self.target.log.debug("", exc_info=e)

    @export(record=BrowserCookieRecord)
    def cookies(self) -> Iterator[BrowserCookieRecord]:
        """Return browser cookie records from Firefox.

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
        for user_details, db_file, db in self._iter_db("cookies.sqlite"):
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
                        _target=self.target,
                        _user=user_details.user if user_details else None,
                    )
            except DBError as e:  # noqa: PERF203
                self.target.log.warning("Error processing cookie file: %s", db_file)
                self.target.log.debug("", exc_info=e)

    @export(record=BrowserDownloadRecord)
    def downloads(self) -> Iterator[BrowserDownloadRecord]:
        """Return browser download records from Firefox.

        Yields BrowserDownloadRecord with the following fields:

        .. code-block:: text

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
        for user_details, db_file, db in self._iter_db("places.sqlite"):
            try:
                places = {row.id: row for row in db.table("moz_places").rows()}
                if not (moz_anno_attributes := db.table("moz_anno_attributes")):
                    continue

                attributes = {row.id: row.name for row in moz_anno_attributes.rows()}
                annotations = {}

                for row in db.table("moz_annos"):
                    attribute_name = attributes.get(row.anno_attribute_id, row.anno_attribute_id)

                    content = json.loads(row.content) if attribute_name == "downloads/metaData" else row.content

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
                        _user=user_details.user if user_details else None,
                    )
            except DBError as e:
                self.target.log.warning("Error processing history file: %s", db_file)
                self.target.log.debug("", exc_info=e)

    @export(record=BrowserExtensionRecord)
    def extensions(self) -> Iterator[BrowserExtensionRecord]:
        """Return browser extension records for Firefox.

        Yields BrowserExtensionRecord with the following fields:

        .. code-block:: text

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
            optional_permissions (string[]): Optional permissions of the extension.
            source_uri (path): Source path from which the extension was downloaded.
            source (path): The source file of the download record.
        """
        for user_details, _, profile_dir in self._iter_profiles():
            if not (extension_file := profile_dir.joinpath("extensions.json")).is_file():
                continue

            try:
                extensions = json.load(extension_file.open())
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                self.target.log.warning(
                    "Firefox file '%s' is malformed, consider inspecting the file manually: %s",
                    extension_file,
                    e,
                )
                self.target.log.debug("", exc_info=e)

            for extension in extensions.get("addons", []):
                yield self.BrowserExtensionRecord(
                    ts_install=from_unix_ms(extension.get("installDate", 0)),
                    ts_update=from_unix_ms(extension.get("updateDate", 0)),
                    browser="firefox",
                    extension_id=extension.get("id"),
                    name=(extension.get("defaultLocale", {}) or {}).get("name"),
                    short_name=None,
                    default_title=None,
                    description=(extension.get("defaultLocale", {}) or {}).get("description"),
                    version=extension.get("version"),
                    ext_path=extension.get("path"),
                    from_webstore=None,
                    permissions=(extension.get("userPermissions", {}) or {}).get("permissions"),
                    manifest_version=extension.get("manifestVersion"),
                    source_uri=extension.get("sourceURI"),
                    optional_permissions=(extension.get("optionalPermissions", {}) or {}).get("permissions"),
                    source=extension_file,
                    _target=self.target,
                    _user=user_details.user if user_details else None,
                )

    @export(record=BrowserPasswordRecord)
    def passwords(self) -> Iterator[BrowserPasswordRecord]:
        """Return Firefox browser password records.

        Automatically decrypts passwords from Firefox 58 onwards (2018) if no primary password is set.
        Alternatively, you can supply a primary password through the keychain to access the Firefox password store.

        Passphrases in the keychain with providers ``browser``, ``firefox``, ``user`` and no provider
        can be used to decrypt secrets for this plugin.

        References:
            - https://github.com/mozilla-firefox/firefox/tree/main/toolkit/components/passwordmgr
            - https://github.com/lclevy/firepwd
        """

        working_passwords = set()

        for user_details, _, profile_dir in self._iter_profiles():
            logins_file = profile_dir.joinpath("logins.json")
            logins_backup = profile_dir.joinpath("logins-backup.json")

            key3_file = profile_dir.joinpath("key3.db")
            key4_file = profile_dir.joinpath("key4.db")

            # Do not attempt master key decryption if this profile has no logins.
            if not logins_file.is_file() and not logins_backup.is_file():
                continue

            if key3_file.is_file() and not key4_file.is_file():
                self.target.log.warning("Unsupported file 'key3.db' found in %s", profile_dir)
                continue

            if not key4_file.is_file():
                self.target.log.warning("No 'key4.db' found in %s", profile_dir)
                continue

            if not HAS_CRYPTO or not HAS_ASN1:
                self.target.log.error("Missing dependencies pycryptodome or asn1crypto for Firefox password decryption")
                continue

            # Decrypt the master key for this profile first. The ``BrowserPlugin.keychain()`` includes an empty password
            # which is required to decrypt Firefox master keys with no primary password set.
            key = None

            for primary_password in itertools.chain(working_passwords, self.keychain()):
                try:
                    key = decrypt_master_key(key4_file, primary_password.encode())
                    working_passwords.add(primary_password)
                    break

                except ValueError as e:
                    self.target.log.debug(
                        "Failed to decrypt Firefox master key using primary password %r: %s", primary_password, e
                    )

            if not key:
                self.target.log.error(
                    "Failed to decrypt Firefox master key in file '%s' using provided passphrase(s)", key4_file
                )
                continue

            for login_file in (logins_file, logins_backup):
                if not login_file.is_file():
                    continue

                try:
                    logins = json.load(login_file.open())
                except (UnicodeDecodeError, json.JSONDecodeError) as e:
                    self.target.log.warning(
                        "Firefox file '%s' is malformed, consider inspecting the file manually: %s",
                        login_file,
                        e,
                    )
                    self.target.log.debug("", exc_info=e)

                for login in logins.get("logins", []):
                    decrypted_username = None
                    decrypted_password = None

                    try:
                        decrypted_username = decrypt_value(login.get("encryptedUsername"), key)
                        decrypted_password = decrypt_value(login.get("encryptedPassword"), key)

                    except ValueError as e:
                        self.target.log.warning(
                            "Exception while trying to decrypt Firefox login in '%s': %s", login_file, e
                        )
                        self.target.log.debug("", exc_info=e)

                    yield self.BrowserPasswordRecord(
                        ts_created=from_unix_ms(login.get("timeCreated", 0)),
                        ts_last_used=from_unix_ms(login.get("timeLastUsed", 0)),
                        ts_last_changed=from_unix_ms(login.get("timePasswordChanged", 0)),
                        browser="firefox",
                        id=login.get("id"),
                        url=login.get("hostname"),
                        encrypted_username=base64.b64decode(login.get("encryptedUsername", ""))
                        if not decrypted_username
                        else None,
                        encrypted_password=base64.b64decode(login.get("encryptedPassword", ""))
                        if not decrypted_password
                        else None,
                        decrypted_username=decrypted_username,
                        decrypted_password=decrypted_password,
                        source=login_file,
                        _target=self.target,
                        _user=user_details.user if user_details else None,
                    )


# Define separately because it is not defined in asn1crypto
pbeWithSha1AndTripleDES_CBC = "1.2.840.113549.1.12.5.1.3"
CKA_ID = bytes.fromhex("f8000000000000000000000000000001")


def _decrypt_master_key_pbes2(decoded_item: core.Sequence, primary_password: bytes, global_salt: bytes) -> bytes:
    """Decrypt a Firefox master key with the given primary password and salt.

    Args:
        decoded_item: ``core.Sequence`` is a ``list`` representation of ``SEQUENCE`` as described below.
        primary_password: ``bytes`` of Firefox primary password to decrypt ciphertext with.
        global_salt: ``bytes`` of salt to prepend to primary password when calculating AES key.

    Raises:
        ValueError: When missing ``pycryptodome`` or ``asn1crypto`` dependencies.

    Returns:
        Bytes of decrypted AES ciphertext.
    """

    # SEQUENCE {
    #   SEQUENCE {
    #     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 => pkcs5 pbes2
    #     SEQUENCE {
    #       SEQUENCE {
    #         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 => pbkdf2
    #         SEQUENCE {
    #           OCTETSTRING 32 bytes, entrySalt
    #           INTEGER 01
    #           INTEGER 20
    #           SEQUENCE {
    #             OBJECTIDENTIFIER 1.2.840.113549.2.9 => hmacWithSHA256
    #           }
    #         }
    #       }
    #       SEQUENCE {
    #         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 => aes256-CBC
    #         OCTETSTRING 14 bytes, iv
    #       }
    #     }
    #   }
    #   OCTETSTRING encrypted
    # }

    pkcs5_oid = decoded_item[0][1][0][0].dotted
    if algos.KdfAlgorithmId.map(pkcs5_oid) != "pbkdf2":
        raise ValueError(f"Expected pbkdf2 object identifier, got: {pkcs5_oid}")

    sha256_oid = decoded_item[0][1][0][1][3][0].dotted
    if algos.HmacAlgorithmId.map(sha256_oid) != "sha256":
        raise ValueError(f"Expected SHA256 object identifier, got: {pkcs5_oid}")

    aes256_cbc_oid = decoded_item[0][1][1][0].dotted
    if algos.EncryptionAlgorithmId.map(aes256_cbc_oid) != "aes256_cbc":
        raise ValueError(f"Expected AES256-CBC object identifier, got: {pkcs5_oid}")

    entry_salt = decoded_item[0][1][0][1][0].native
    iteration_count = decoded_item[0][1][0][1][1].native
    key_length = decoded_item[0][1][0][1][2].native

    if key_length != 32:
        raise ValueError(f"Expected key_length to be 32, got: {key_length}")

    k = sha1(global_salt + primary_password).digest()
    key = pbkdf2_hmac("sha256", k, entry_salt, iteration_count, dklen=key_length)

    iv = b"\x04\x0e" + decoded_item[0][1][1][1].native
    cipher_text = decoded_item[1].native
    return AES.new(key, AES.MODE_CBC, iv).decrypt(cipher_text)


def _decrypt_master_key(decoded_item: core.Sequence, primary_password: bytes, global_salt: bytes) -> tuple[bytes, str]:
    """Decrypt the provided ``core.Sequence`` with the provided Firefox primary password and salt.

    At this stage we are not yet sure of the structure of ``decoded_item``. The structure will depend on the
    ``core.Sequence`` object identifier at ``decoded_item[0][0]``, hence we extract it. This function will
    then call the apropriate ``_decrypt_master_key_pbes2`` function to decrypt the item.

    Firefox supports other algorithms (i.e. Firefox before 2018 and ``pbeWithSha1AndTripleDES-CBC`` from ``key3.db``
    files), but decrypting these is not (yet) supported by this plugin.

    Args:
        decoded_item: ``core.Sequence`` is a ``list`` representation of ``SEQUENCE`` as described below.
        primary_password: ``bytes`` of Firefox primary password to decrypt ciphertext with.
        global_salt: ``bytes`` of salt to prepend to primary password when calculating AES key.

    Returns:
        Tuple of decrypted bytes and a dotted ASN.1 string representation of the identified encryption algorithm.
    """

    # SEQUENCE {
    #     SEQUENCE {
    #         OBJECTIDENTIFIER ???
    #         ...
    #     }
    #     ...
    # }

    object_identifier = decoded_item[0][0]
    algorithm = object_identifier.dotted

    if algos.EncryptionAlgorithmId.map(algorithm) == "pbes2":
        return _decrypt_master_key_pbes2(decoded_item, primary_password, global_salt), algorithm

    raise ValueError(f"Unsupported Firefox master key encryption algorihm {algorithm!s}")


def decrypt_master_key(key4_file: Path, primary_password: bytes) -> bytes:
    """Retrieve and decrypt the master key from the Firefox NSS database.

    Args:
        key4_file: Path object to the ``key4.db`` file.
        primary_password: bytes of the Firefox primary password.

    Raises:
        ValueError if retrieval or decryption of master key fails.

    Returns:
        32 byte or 24 byte long decrypted and unpadded master key for AES or 3DES operations.
    """

    # Extract neccesary information from the key4.db file. Multiple values might exist for the
    # values we are interested in. Generally the last entry will be the currently active value,
    # which is why we need to iterate every row in the table to get the last entry.
    with SQLite3(key4_file) as db:
        # Get the last ``item`` (global salt) and ``item2`` (password check) values.
        if table := db.table("metadata"):
            for row in table.rows():
                if row.get("id") == "password":
                    global_salt = row.get("item1", b"")
                    password_check = row.get("item2", b"")
        else:
            raise ValueError(f"Missing table 'metadata' in key4.db {key4_file}")

        # Get the last ``a11`` (master key) and ``a102`` (cka) values.
        if table := db.table("nssPrivate"):
            *_, last_row = table.rows()
            master_key = last_row.get("a11")
            master_key_cka = last_row.get("a102")
        else:
            raise ValueError(f"Missing table 'nssPrivate' in key4.db {key4_file}")

        if not master_key:
            raise ValueError(f"Password master key is not defined in key4.db {key4_file}")

        if master_key_cka != CKA_ID:
            raise ValueError(
                f"Password master key CKA_ID '{master_key_cka}' is not equal to expected value '{CKA_ID}' in {key4_file}"  # noqa: E501
            )

        decoded_password_check: core.Sequence = core.load(password_check)
        decoded_master_key: core.Sequence = core.load(master_key)

        try:
            decrypted_password_check, algorithm = _decrypt_master_key(
                decoded_password_check, primary_password, global_salt
            )

        except EOFError:
            raise ValueError("No primary password provided")

        except ValueError as e:
            raise ValueError(f"Unable to decrypt Firefox password check: {e!s}") from e

        if not decrypted_password_check:
            raise ValueError(f"Encountered unknown algorithm {algorithm} while decrypting Firefox master key")

        expected_password_check = b"password-check\x02\x02"

        if decrypted_password_check != expected_password_check:
            log.debug("Expected %s but got %s", expected_password_check, decrypted_password_check)
            raise ValueError("Master key decryption failed. Provided password could be missing or incorrect")

        decrypted, algorithm = _decrypt_master_key(decoded_master_key, primary_password, global_salt)

        block_size = 16 if algos.EncryptionAlgorithmId.map(algorithm) == "pbes2" else 8

        return unpad(decrypted, block_size)


def decrypt_value(b64_ciphertext: str, key: bytes) -> bytes | None:
    """Decrypt an encrypted value using the decrypted master key and algorithm.

    Args:
        b64_ciphertext: Base64 encoded ciphertext.
        key: Decrypted Firefox master key.

    Returns:
        Decrypted bytes or None.

    Raises:
        ValueError if decryption fails.

    References:
        - https://github.com/lclevy/firepwd
        - https://github.com/Sohimaster/Firefox-Passwords-Decryptor/
        - https://github.com/mozilla-firefox/firefox/tree/main/toolkit/components/passwordmgr
        - https://github.com/mozilla-firefox/firefox/blob/main/security/manager/ssl/SecretDecoderRing.cpp
        - https://github.com/mozilla-firefox/firefox/blob/main/security/nss/lib/pk11wrap/pk11sdr.c#L156
    """

    if not HAS_CRYPTO:
        raise ValueError("Missing pycryptodome dependency")

    if not HAS_ASN1:
        raise ValueError("Missing asn1crypto dependency")

    if not b64_ciphertext:
        raise ValueError("No base64 encoded ciphertext provided")

    try:
        buf = b64decode(b64_ciphertext)
    except ValueError as e:
        raise ValueError("Failed to decode Firefox base64 encoded ciphertext") from e

    # Split the key_id, iv and ciphertext
    if buf.startswith(b"v10"):
        key_id = buf[3:19]
        iv = buf[19:31]  # AES-GCM with 12 byte iv
        ciphertext = buf[31:]

    else:
        # Firefox ASN.1 format
        # SEQUENCE {
        #     KEY_ID
        #     SEQUENCE {
        #         OBJECT_IDENTIFIER
        #         IV
        #     }
        #     CIPHERTEXT
        # }
        decoded = core.load(buf)
        key_id = decoded[0].native
        iv = decoded[1][1].native
        ciphertext = decoded[2].native

    if key_id != CKA_ID:
        raise ValueError(f"Expected cka to equal '{CKA_ID}' but got '{key_id}'")

    # Decrypt the ciphertext
    if len(iv) == 16 and len(key) == 32:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    elif len(iv) == 12:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    elif len(iv) == 8:
        cipher = DES3.new(key, DES3.MODE_CBC, iv)

    else:
        raise ValueError(f"Unexpected IV length of {len(iv)} and/or key length of {len(key)}")

    return unpad(cipher.decrypt(ciphertext), cipher.block_size)
