from __future__ import annotations

import base64
import hmac
import json
import logging
from base64 import b64decode
from hashlib import pbkdf2_hmac, sha1
from itertools import chain
from typing import TYPE_CHECKING

from dissect.sql import sqlite3
from dissect.sql.exceptions import Error as SQLError
from dissect.util.ts import from_unix_ms, from_unix_us

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
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

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.plugins.general.users import UserRecord
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

log = logging.getLogger(__name__)


class FirefoxPlugin(BrowserPlugin):
    """Firefox browser plugin."""

    __namespace__ = "firefox"

    USER_DIRS = (
        # Windows
        "AppData/Roaming/Mozilla/Firefox/Profiles",
        "AppData/local/Mozilla/Firefox/Profiles",
        # Linux
        ".mozilla/firefox",
        "snap/firefox/common/.mozilla/firefox",
        ".var/app/org.mozilla.firefox/.mozilla/firefox",
        # macOS
        "Library/Application Support/Firefox",
    )

    SYSTEM_DIRS = ("/data/data/org.mozilla.vrbrowser/files/mozilla",)

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
        self.dirs: list[tuple[UserRecord, TargetPath]] = []

        for user_details in self.target.user_details.all_with_home():
            for directory in self.USER_DIRS:
                cur_dir = user_details.home_path.joinpath(directory)
                if not cur_dir.exists():
                    continue
                self.dirs.append((user_details.user, cur_dir))

        for directory in self.SYSTEM_DIRS:
            if (cur_dir := target.fs.path(directory)).exists():
                self.dirs.append((None, cur_dir))

    def check_compatible(self) -> None:
        if not len(self.dirs):
            raise UnsupportedPluginError("No Firefox directories found")

    def _iter_profiles(self) -> Iterator[tuple[UserRecord, TargetPath, TargetPath]]:
        """Yield user directories."""
        for user, cur_dir in self.dirs:
            for profile_dir in cur_dir.iterdir():
                if not profile_dir.is_dir():
                    continue
                yield user, cur_dir, profile_dir

    def _iter_db(self, filename: str) -> Iterator[tuple[UserRecord, SQLite3]]:
        """Yield opened history database files of all users.

        Args:
            filename: The filename of the database.

        Yields:
            Opened SQLite3 databases.
        """
        iter_system = ((None, system_dir, None) for user, system_dir in self.dirs if user is None)

        for user, cur_dir, profile_dir in chain(iter_system, self._iter_profiles()):
            if user is None and profile_dir is None:
                db_file = cur_dir.parent.joinpath(filename)
                # On some Android variants, some files may exist in the base directory (places.sqlite) but others
                # in a nested profile directory (cookies.sqlite)
                # /data/data/org.mozilla.vrbrowser/files/places.sqlite
                # /data/data/org.mozilla.vrbrowser/files/mozilla/xxxxxx.default/cookies.sqlite
                if not db_file.exists():
                    continue
            else:
                db_file = profile_dir.joinpath(filename)

            try:
                yield user, db_file, sqlite3.SQLite3(db_file.open())
            except FileNotFoundError:
                self.target.log.info("Could not find %s file: %s", filename, db_file)
            except SQLError as e:
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
        from_timestamp = from_unix_ms if self.target.os == OperatingSystem.ANDROID else from_unix_us

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
                        ts=from_timestamp(row.visit_date),
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
            except SQLError as e:  # noqa: PERF203
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
                        _target=self.target,
                        _user=user,
                    )
            except SQLError as e:  # noqa: PERF203
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
        for user, db_file, db in self._iter_db("places.sqlite"):
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
                        _user=user,
                    )
            except SQLError as e:
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
        for user, _, profile_dir in self._iter_profiles():
            extension_file = profile_dir.joinpath("extensions.json")

            if not extension_file.exists():
                self.target.log.warning(
                    "No 'extensions.json' addon file found for user %s in directory %s",
                    user.name,
                    profile_dir,
                )
                continue

            try:
                extensions = json.load(extension_file.open())

                for extension in extensions.get("addons", []):
                    yield self.BrowserExtensionRecord(
                        ts_install=from_unix_ms(extension.get("installDate", 0)),
                        ts_update=from_unix_ms(extension.get("updateDate", 0)),
                        browser="firefox",
                        id=extension.get("id"),
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
                        _user=user,
                    )

            except FileNotFoundError:
                self.target.log.info(
                    "No 'extensions.json' addon file found for user %s in directory %s",
                    user.name,
                    profile_dir,
                )
            except json.JSONDecodeError:
                self.target.log.warning(
                    "extensions.json file in directory %s is malformed, consider inspecting the file manually",
                    profile_dir,
                )

    @export(record=BrowserPasswordRecord)
    def passwords(self) -> Iterator[BrowserPasswordRecord]:
        """Return Firefox browser password records.

        Automatically decrypts passwords from Firefox 58 onwards (2018) if no primary password is set.
        Alternatively, you can supply a primary password through the keychain to access the Firefox password store.

        ``PASSPHRASE`` passwords in the keychain with providers ``browser``, ``firefox``, ``user`` and no provider
        can be used to decrypt secrets for this plugin.

        Resources:
            - https://github.com/lclevy/firepwd
        """
        for user, _, profile_dir in self._iter_profiles():
            login_file = profile_dir.joinpath("logins.json")
            key3_file = profile_dir.joinpath("key3.db")
            key4_file = profile_dir.joinpath("key4.db")

            if not login_file.exists():
                self.target.log.warning(
                    "No 'logins.json' password file found for user %s in directory %s",
                    user.name,
                    profile_dir,
                )
                continue

            if key3_file.exists() and not key4_file.exists():
                self.target.log.warning("Unsupported file 'key3.db' found in %s", profile_dir)
                continue

            if not key4_file.exists():
                self.target.log.warning("No 'key4.db' found in %s", profile_dir)
                continue

            try:
                logins = json.load(login_file.open())

                for login in logins.get("logins", []):
                    decrypted_username = None
                    decrypted_password = None

                    for password in self.keychain():
                        try:
                            decrypted_username, decrypted_password = decrypt(
                                login.get("encryptedUsername"),
                                login.get("encryptedPassword"),
                                key4_file,
                                password,
                            )
                        except ValueError as e:
                            self.target.log.warning("Exception while trying to decrypt")
                            self.target.log.debug("", exc_info=e)

                        if decrypted_password and decrypted_username:
                            break

                    yield self.BrowserPasswordRecord(
                        ts_created=from_unix_ms(login.get("timeCreated", 0)),
                        ts_last_used=from_unix_ms(login.get("timeLastUsed", 0)),
                        ts_last_changed=from_unix_ms(login.get("timePasswordChanged", 0)),
                        browser="firefox",
                        id=login.get("id"),
                        url=login.get("hostname"),
                        encrypted_username=base64.b64decode(login.get("encryptedUsername", "")),
                        encrypted_password=base64.b64decode(login.get("encryptedPassword", "")),
                        decrypted_username=decrypted_username,
                        decrypted_password=decrypted_password,
                        source=login_file,
                        _target=self.target,
                        _user=user,
                    )

            except FileNotFoundError:
                self.target.log.info(
                    "No password file found for user %s in directory %s",
                    user.name,
                    profile_dir,
                )
            except json.JSONDecodeError:
                self.target.log.warning(
                    "logins.json file in directory %s is malformed, consider inspecting the file manually",
                    profile_dir,
                )


# Define separately because it is not defined in asn1crypto
pbeWithSha1AndTripleDES_CBC = "1.2.840.113549.1.12.5.1.3"
CKA_ID = b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"


def decrypt_moz_3des(global_salt: bytes, primary_password: bytes, entry_salt: str, encrypted: bytes) -> bytes:
    if not HAS_CRYPTO:
        raise ValueError("Missing pycryptodome dependency")

    hp = sha1(global_salt + primary_password).digest()
    pes = entry_salt + b"\x00" * (20 - len(entry_salt))
    chp = sha1(hp + entry_salt).digest()
    k1 = hmac.new(chp, pes + entry_salt, sha1).digest()
    tk = hmac.new(chp, pes, sha1).digest()
    k2 = hmac.new(chp, tk + entry_salt, sha1).digest()
    k = k1 + k2
    iv = k[-8:]
    key = k[:24]
    return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encrypted)


def decode_login_data(data: str) -> tuple[bytes, bytes, bytes]:
    """Decode Firefox login data.

    Args:
        data: Base64 encoded data in string format.

    Raises:
        ValueError: When missing ``pycryptodome`` or ``asn1crypto`` dependencies.

    Returns:
        Tuple of bytes with ``key_id``, ``iv`` and ``ciphertext``
    """

    # SEQUENCE {
    #     KEY_ID
    #     SEQUENCE {
    #         OBJECT_IDENTIFIER
    #         IV
    #     }
    #     CIPHERTEXT
    # }

    if not HAS_CRYPTO:
        raise ValueError("Missing pycryptodome dependency")

    if not HAS_ASN1:
        raise ValueError("Missing asn1crypto dependency")

    decoded = core.load(b64decode(data))
    key_id = decoded[0].native
    iv = decoded[1][1].native
    ciphertext = decoded[2].native
    return key_id, iv, ciphertext


def decrypt_pbes2(decoded_item: core.Sequence, primary_password: bytes, global_salt: bytes) -> bytes:
    """Decrypt an item with the given primary password and salt.

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

    if not HAS_CRYPTO:
        raise ValueError("Missing pycryptodome dependency")

    if not HAS_ASN1:
        raise ValueError("Missing asn1crypto dependency")

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


def decrypt_sha1_triple_des_cbc(decoded_item: core.Sequence, primary_password: bytes, global_salt: bytes) -> bytes:
    """Decrypt an item with the given Firefox primary password and salt.

    Args:
        decoded_item: ``core.Sequence`` is a ``list`` representation of ``SEQUENCE`` as described below.
        primary_password: ``bytes`` of Firefox primary password to decrypt ciphertext with.
        global_salt: ``bytes`` of salt to prepend to primary password when calculating AES key.

    Raises:
        ValueError: When missing ``pycryptodome`` or ``asn1crypto`` dependencies.

    Returns:
        Bytes of decrypted 3DES ciphertext.
    """

    # SEQUENCE {
    #     SEQUENCE {
    #         OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
    #         SEQUENCE {
    #             OCTETSTRING entry_salt
    #             INTEGER 01
    #         }
    #     }
    #     OCTETSTRING encrypted
    # }

    entry_salt = decoded_item[0][1][0].native
    cipher_text = decoded_item[1].native
    key = decrypt_moz_3des(global_salt, primary_password, entry_salt, cipher_text)
    return key[:24]


def decrypt_master_key(decoded_item: core.Sequence, primary_password: bytes, global_salt: bytes) -> tuple[bytes, str]:
    """Decrypt the provided ``core.Sequence`` with the provided Firefox primary password and salt.

    At this stage we are not yet sure of the structure of ``decoded_item``. The structure will depend on the
    ``core.Sequence`` object identifier at ``decoded_item[0][0]``, hence we extract it. This function will
    then call the apropriate ``decrypt_pbes2``or ``decrypt_sha1_triple_des_cbc`` functions to decrypt the item.

    Args:
        decoded_item: ``core.Sequence`` is a ``list`` representation of ``SEQUENCE`` as described below.
        primary_password: ``bytes`` of Firefox primary password to decrypt ciphertext with.
        global_salt: ``bytes`` of salt to prepend to primary password when calculating AES key.

    Raises:
        ValueError: When missing ``pycryptodome`` or ``asn1crypto`` dependencies.

    Returns:
        Tuple of decrypted bytes and a string representation of the identified encryption algorithm.
    """

    # SEQUENCE {
    #     SEQUENCE {
    #         OBJECTIDENTIFIER ???
    #         ...
    #     }
    #     ...
    # }

    if not HAS_CRYPTO:
        raise ValueError("Missing pycryptodome dependency")

    if not HAS_ASN1:
        raise ValueError("Missing asn1crypto depdendency")

    object_identifier = decoded_item[0][0]
    algorithm = object_identifier.dotted

    if algos.EncryptionAlgorithmId.map(algorithm) == "pbes2":
        return decrypt_pbes2(decoded_item, primary_password, global_salt), algorithm
    if algorithm == pbeWithSha1AndTripleDES_CBC:
        return decrypt_sha1_triple_des_cbc(decoded_item, primary_password, global_salt), algorithm
    # Firefox supports other algorithms (i.e. Firefox before 2018), but decrypting these is not (yet) supported.
    return b"", algorithm


def query_global_salt(key4_file: TargetPath) -> tuple[str, str]:
    with key4_file.open("rb") as fh:
        db = sqlite3.SQLite3(fh)
        for row in db.table("metadata").rows():
            if row.get("id") == "password":
                return row.get("item1", ""), row.get("item2", "")
        return None


def query_master_key(key4_file: TargetPath) -> tuple[str, str]:
    with key4_file.open("rb") as fh:
        db = sqlite3.SQLite3(fh)
        if row := next(db.table("nssPrivate").rows(), None):
            return row.get("a11", ""), row.get("a102", "")
        return None


def retrieve_master_key(primary_password: bytes, key4_file: TargetPath) -> tuple[bytes, str]:
    if not HAS_CRYPTO:
        raise ValueError("Missing pycryptodome dependency")

    if not HAS_ASN1:
        raise ValueError("Missing asn1crypto dependency")

    global_salt, password_check = query_global_salt(key4_file)
    decoded_password_check = core.load(password_check)

    try:
        decrypted_password_check, algorithm = decrypt_master_key(decoded_password_check, primary_password, global_salt)
    except EOFError:
        raise ValueError("No primary password provided")

    if not decrypted_password_check:
        raise ValueError(f"Encountered unknown algorithm {algorithm} while decrypting master key")

    expected_password_check = b"password-check\x02\x02"
    if decrypted_password_check != b"password-check\x02\x02":
        log.debug("Expected %s but got %s", expected_password_check, decrypted_password_check)
        raise ValueError("Master key decryption failed. Provided password could be missing or incorrect")

    master_key, master_key_cka = query_master_key(key4_file)
    if master_key == b"":
        raise ValueError("Password master key is not defined")

    if master_key_cka != CKA_ID:
        raise ValueError(f"Password master key CKA_ID '{master_key_cka}' is not equal to expected value '{CKA_ID}'")

    decoded_master_key = core.load(master_key)
    decrypted, algorithm = decrypt_master_key(decoded_master_key, primary_password, global_salt)
    return decrypted[:24], algorithm


def decrypt_field(key: bytes, field: tuple[bytes, bytes, bytes]) -> bytes:
    if not HAS_CRYPTO:
        raise ValueError("Missing pycryptodome dependency")

    cka, iv, ciphertext = field

    if cka != CKA_ID:
        raise ValueError(f"Expected cka to equal '{CKA_ID}' but got '{cka}'")

    return unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext), 8)


def decrypt(
    username: str, password: str, key4_file: TargetPath, primary_password: str = ""
) -> tuple[str | None, str | None]:
    """Decrypt a stored username and password using provided credentials and key4 file.

    Args:
        username: Encoded and encrypted password.
        password Encoded and encrypted password.
        key4_file: Path to key4.db file.
        primary_password: Password to use for decryption routine.

    Returns:
        A tuple of decoded username and password strings.

    Resources:
        - https://github.com/lclevy/firepwd
    """
    if not HAS_CRYPTO:
        raise ValueError("Missing pycryptodome dependency")

    if not HAS_ASN1:
        raise ValueError("Missing asn1crypto dependency")

    try:
        username = decode_login_data(username)
        password = decode_login_data(password)

        primary_password_bytes = primary_password.encode()
        key, algorithm = retrieve_master_key(primary_password_bytes, key4_file)

        if algorithm == pbeWithSha1AndTripleDES_CBC or algos.EncryptionAlgorithmId.map(algorithm) == "pbes2":
            username = decrypt_field(key, username)
            password = decrypt_field(key, password)
            return username.decode(), password.decode()

    except ValueError as e:
        raise ValueError(f"Failed to decrypt password using keyfile: {key4_file}, password: {primary_password}") from e
