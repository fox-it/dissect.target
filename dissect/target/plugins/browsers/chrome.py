from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import (
    GENERIC_DOWNLOAD_RECORD_FIELDS,
    GENERIC_EXTENSION_RECORD_FIELDS,
    GENERIC_HISTORY_RECORD_FIELDS,
)
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
        ".var/app/com.google.Chrome/config/google-chrome/Default",
        # Macos
        "Library/Application Support/Google/Chrome/Default",
    ]
    BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/chrome/download", GENERIC_DOWNLOAD_RECORD_FIELDS
    )
    BrowserExtensionRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/chrome/extension", GENERIC_EXTENSION_RECORD_FIELDS
    )
    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/chrome/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    @export(record=BrowserDownloadRecord)
    def downloads(self):
        """Return browser download records for Google Chrome."""
        yield from super().downloads("chrome")

    @export(record=BrowserExtensionRecord)
    def extensions(self):
        """Return browser extension records for Google Chrome."""
        yield from super().extensions("chrome")

    @export(record=BrowserHistoryRecord)
    def history(self):
        """Return browser history records for Google Chrome."""
        yield from super().history("chrome")
