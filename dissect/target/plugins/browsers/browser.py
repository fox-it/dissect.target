from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

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


class BrowserPlugin(Plugin):
    """General browser plugin.

    This plugin groups the functions of all browser plugins. For example,
    instead of having to run both firefox.history and chrome.history,
    you only have to run browser.history to get output from both browsers.
    """

    __namespace__ = "browser"
    __findable__ = False

    BROWSERS = [
        "chrome",
        "chromium",
        "edge",
        "firefox",
        "iexplore",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._plugins = []
        for entry in self.BROWSERS:
            try:
                self._plugins.append(getattr(self.target, entry))
            except Exception:
                target.log.exception("Failed to load browser plugin: %s", entry)

    def _func(self, func_name: str):
        """Return the supported browser plugin records.

        Args:
            func_name: Exported function of the browser plugin to find.

        Yields:
            Record from the browser function.
        """
        for plugin_name in self._plugins:
            try:
                for entry in getattr(plugin_name, func_name)():
                    yield entry
            except Exception:
                self.target.log.exception("Failed to execute browser plugin: %s.%s", plugin_name._name, func_name)

    def check_compatible(self) -> bool:
        if not len(self._plugins):
            raise UnsupportedPluginError("No compatible browser plugins found")

    @export(record=BrowserDownloadRecord)
    def downloads(self):
        """Return browser download records from all browsers installed and supported.

        Yields BrowserDownloadRecord with the following fields:
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
        """
        yield from self._func("downloads")

    @export(record=BrowserExtensionRecord)
    def extensions(self):
        """Return browser extensions from all browsers installed and supported.

        Browser extensions for Chrome, Chromium, and Edge (Chromium).

        Yields BrowserExtensionRecord with the following fields:
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
        yield from self._func("extensions")

    @export(record=BrowserHistoryRecord)
    def history(self):
        """Return browser history records from all browsers installed and supported.

        Historical browser records for Chrome, Chromium, Edge (Chromium), Firefox, and Internet Explorer are returned.

        Yields BrowserHistoryRecord with the following fields:
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
        yield from self._func("history")


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
