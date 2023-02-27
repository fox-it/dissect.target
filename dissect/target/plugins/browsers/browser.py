from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

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
            except Exception:  # noqa
                target.log.exception("Failed to load browser plugin: %s", entry)

    def check_compatible(self):
        if not len(self._plugins):
            raise UnsupportedPluginError("No compatible browser plugins found")

    def _func(self, f):
        for p in self._plugins:
            try:
                for entry in getattr(p, f)():
                    yield entry
            except Exception:
                self.target.log.exception("Failed to execute browser plugin: %s.%s", p._name, f)

    @export(record=BrowserHistoryRecord)
    def history(self):
        """Return browser history records from all browsers installed.

        Historical browser records for Chrome, Chromium, Edge (Chromium), Firefox, and Internet Explorer are returned.

        Yields BrowserHistoryRecords with the following fields:
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
        for e in self._func("history"):
            yield e


def try_idna(s):
    try:
        return s.encode("idna")
    except Exception:  # noqa
        return s
