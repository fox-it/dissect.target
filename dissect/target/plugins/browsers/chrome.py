from dissect.target import Target
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import GENERIC_HISTORY_RECORD_FIELDS
from dissect.target.plugins.browsers.chromiummixin import ChromiumMixin

ChromeBrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browser/chrome/history", GENERIC_HISTORY_RECORD_FIELDS
)


class ChromePlugin(ChromiumMixin, Plugin):
    """Chrome browser plugin.

    Yields: ChromeBrowserHistoryRecord
    """

    __namespace__ = "chrome"

    DIRS: list = [
        # Windows
        "AppData/Local/Google/Chrome/User Data/Default",
        "AppData/Local/Google/Chrome/continuousUpdates/User Data/Default",
        "Local Settings/Application Data/Google/Chrome/User Data/Default",
        "AppData/local/Google/Chromium/User Data/Default",
        # Linux
        ".config/google-chrome/Default",
        "snap/chromium/common/chromium/Default",
        # Macos
        "Library/Application Support/Google/Chrome/Default",
    ]
    HISTORY_RECORD = ChromeBrowserHistoryRecord

    def __init__(self, target: Target):
        super().__init__(target)

    def check_compatible(self):
        """Perform a compatibility check with the target."""
        ChromiumMixin.check_compatible(self)

    @export(record=HISTORY_RECORD)
    def history(self):
        """Return browser history records for Google Chrome."""
        yield from ChromiumMixin.history(self, "chrome")
