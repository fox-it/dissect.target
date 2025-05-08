from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING

from dissect.target.helpers import keychain
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import NamespacePlugin

if TYPE_CHECKING:
    from dissect.target.target import Target

GENERIC_DOWNLOAD_RECORD_FIELDS = [
    ("datetime", "ts_start"),
    ("datetime", "ts_end"),
    ("string", "browser"),
    ("varint", "id"),
    ("path", "path"),
    ("uri", "url"),
    ("filesize", "size"),
    ("varint", "state"),
    ("path", "source"),
]

GENERIC_EXTENSION_RECORD_FIELDS = [
    ("datetime", "ts_install"),
    ("datetime", "ts_update"),
    ("string", "browser"),
    ("string", "id"),
    ("string", "name"),
    ("string", "short_name"),
    ("string", "default_title"),
    ("string", "description"),
    ("string", "version"),
    ("path", "ext_path"),
    ("boolean", "from_webstore"),
    ("string[]", "permissions"),
    ("varint", "manifest_version"),
    ("path", "source"),
]

GENERIC_COOKIE_FIELDS = [
    ("datetime", "ts_created"),
    ("datetime", "ts_last_accessed"),
    ("string", "browser"),
    ("string", "name"),
    ("string", "value"),
    ("string", "host"),
    ("string", "path"),
    ("varint", "expiry"),
    ("boolean", "is_secure"),
    ("boolean", "is_http_only"),
    ("boolean", "same_site"),
    ("path", "source"),
]

GENERIC_HISTORY_RECORD_FIELDS = [
    ("datetime", "ts"),
    ("string", "browser"),
    ("string", "id"),
    ("uri", "url"),
    ("string", "title"),
    ("string", "description"),
    ("string", "rev_host"),
    ("varint", "visit_type"),
    ("varint", "visit_count"),
    ("string", "hidden"),
    ("string", "typed"),
    ("varint", "session"),
    ("varint", "from_visit"),
    ("uri", "from_url"),
    ("path", "source"),
]

GENERIC_PASSWORD_RECORD_FIELDS = [
    ("datetime", "ts_created"),
    ("datetime", "ts_last_used"),
    ("datetime", "ts_last_changed"),
    ("string", "browser"),
    ("varint", "id"),
    ("uri", "url"),
    ("bytes", "encrypted_username"),
    ("bytes", "encrypted_password"),
    ("bytes", "encrypted_notes"),
    ("string", "decrypted_username"),
    ("string", "decrypted_password"),
    ("string", "decrypted_notes"),
    ("path", "source"),
]

BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browser/download", GENERIC_DOWNLOAD_RECORD_FIELDS
)
BrowserExtensionRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browser/extension", GENERIC_EXTENSION_RECORD_FIELDS
)
BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browser/history", GENERIC_HISTORY_RECORD_FIELDS
)
BrowserCookieRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browser/cookie", GENERIC_COOKIE_FIELDS
)
BrowserPasswordRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browser/password", GENERIC_PASSWORD_RECORD_FIELDS
)


class BrowserPlugin(NamespacePlugin):
    __namespace__ = "browser"

    def __init__(self, target: Target):
        super().__init__(target)
        self.keychain = cache(self.keychain)

    def keychain(self) -> set:
        """Retrieve a set of passphrases to use for decrypting saved browser credentials.

        Always adds an empty passphrase as some browsers encrypt values using empty passphrases.

        Returns:
            Set of passphrase strings.
        """
        passphrases = set()
        for provider in [self.__namespace__, "browser", "user", None]:
            for key in keychain.get_keys_for_provider(provider) if provider else keychain.get_keys_without_provider():
                if key.key_type == keychain.KeyType.PASSPHRASE:
                    passphrases.add(key.value)

        passphrases.add("")
        return passphrases


def try_idna(url: str) -> bytes:
    """Attempts to convert a possible Unicode url to ASCII using the IDNA standard.

    Args:
        url: A String containing the url to be converted.

    Returns: Bytes object with the ASCII version of the url.
    """
    try:
        return url.encode("idna")
    except Exception:
        return url
