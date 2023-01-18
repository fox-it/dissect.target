from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import GENERIC_HISTORY_RECORD_FIELDS
from dissect.target.plugins.browsers.chromium import ChromiumMixin


class ChromePlugin(ChromiumMixin, Plugin):
    """Chrome browser plugin."""

    __namespace__ = "chrome"

    DIRS = [
        # Windows
        "AppData/Local/Google/Chrome/User Data/Default",
        "AppData/Local/Google/Chrome/continuousUpdates/User Data/Default",
        "Local Settings/Application Data/Google/Chrome/User Data/Default",
        # Linux
        ".config/google-chrome/Default",
        # Macos
        "Library/Application Support/Google/Chrome/Default",
    ]
    HISTORY_RECORD = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/chrome/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    @export(record=HISTORY_RECORD)
    def history(self):
        """Return browser history records for Google Chrome."""
        yield from ChromiumMixin.history(self, "chrome")
