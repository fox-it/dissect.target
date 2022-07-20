from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.helpers.record import TargetRecordDescriptor


GENERIC_HISTORY_RECORD_FIELDS = [
    ("datetime", "lastvisited"),
    ("string", "browser"),
    ("string", "id"),
    ("uri", "url"),
    ("string", "title"),
    ("string", "rev_host"),
    ("varint", "visit_count"),
    ("string", "hidden"),
    ("string", "typed"),
    ("string", "source"),
]

BrowserHistoryRecord = TargetRecordDescriptor("browsers/history", GENERIC_HISTORY_RECORD_FIELDS)


class BrowserPlugin(Plugin):
    """General browser plugin.

    This plugin groups the functions of all browser plugins. For example,
    instead of having to run both firefox.history and chrome.history,
    you only have to run browser.history to get output from both browsers.
    """

    __namespace__ = "browser"
    BROWSERS = [
        "firefox",
        "chrome",
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

        Historical browser records for Internet Explorer, Chrome and Firefox are returned.

        Yields BrowserHistoryRecords with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            browser (string): The browser from which the records are generated from.
            id (string): Record ID.
            url (uri): History URL.
            title (string): Page title.
            rev_host (string): Reverse hostname.
            lastvisited (datetime): Last visited date and time.
            visit_count (varint): Amount of visits.
            hidden (string): Hidden value.
            typed (string): Typed value.
        """
        for e in self._func("history"):
            yield e


def try_idna(s):
    try:
        return s.encode("idna")
    except Exception:  # noqa
        return s
