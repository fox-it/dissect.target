from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.browser.browser import (
    GENERIC_DOWNLOAD_RECORD_FIELDS,
    GENERIC_EXTENSION_RECORD_FIELDS,
    GENERIC_HISTORY_RECORD_FIELDS,
    BrowserPlugin,
)
from dissect.target.plugins.apps.browser.chromium import (
    CHROMIUM_DOWNLOAD_RECORD_FIELDS,
    ChromiumMixin,
)


class EdgePlugin(ChromiumMixin, BrowserPlugin):
    """Edge browser plugin."""

    __namespace__ = "edge"

    DIRS = [
        # Linux
        ".config/microsoft-edge/Default/",
        ".var/app/com.microsoft.Edge/config/microsoft-edge/Default",
        # Windows
        "AppData/Local/Microsoft/Edge/User Data/Default",
        # Macos
        "Library/Application Support/Microsoft Edge/Default",
    ]
    BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/edge/download", GENERIC_DOWNLOAD_RECORD_FIELDS + CHROMIUM_DOWNLOAD_RECORD_FIELDS
    )
    BrowserExtensionRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/edge/extension", GENERIC_EXTENSION_RECORD_FIELDS
    )
    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/edge/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    @export(record=BrowserDownloadRecord)
    def downloads(self):
        """Return browser download records for Microsoft Edge."""
        yield from super().downloads("edge")

    @export(record=BrowserExtensionRecord)
    def extensions(self):
        """Return browser extension records for Microsoft Edge."""
        yield from super().extensions("edge")

    @export(record=BrowserHistoryRecord)
    def history(self):
        """Return browser history records for Microsoft Edge."""
        yield from super().history("edge")
