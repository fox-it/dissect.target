from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import NamespacePlugin

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
BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browser/download", GENERIC_DOWNLOAD_RECORD_FIELDS
)
BrowserExtensionRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browser/extension", GENERIC_EXTENSION_RECORD_FIELDS
)
BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browser/history", GENERIC_HISTORY_RECORD_FIELDS
)


class BrowserPlugin(NamespacePlugin):
    __namespace__ = "browser"


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
