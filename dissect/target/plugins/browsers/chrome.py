from dissect.target import Target
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.chromium import (
    ChromiumPlugin,
    ChromiumBrowserHistoryRecord,
)


class ChromePlugin(Plugin):
    """Chrome browser plugin.

    ChromiumPlugin contains all logic and configuration.
    """

    __namespace__ = "chrome"

    def __init__(self, target: Target):
        super().__init__(target)
        self.chromium_hist: ChromiumPlugin = ChromiumPlugin(self.target)

    def check_compatible(self):
        self.chromium_hist.check_compatible()

    @export(record=ChromiumBrowserHistoryRecord)
    def history(self):
        """Return browser history records from Google Chrome.

        Yields ChromiumBrowserHistoryRecords with the following fields:
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
        yield from self.chromium_hist.chrome()
