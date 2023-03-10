from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import (
    GENERIC_DOWNLOAD_RECORD_FIELDS,
    GENERIC_HISTORY_RECORD_FIELDS,
)
from dissect.target.plugins.browsers.chromium import ChromiumMixin


class EdgePlugin(ChromiumMixin, Plugin):
    """Edge browser plugin."""

    __namespace__ = "edge"

    DIRS = [
        # Windows
        "AppData/Local/Microsoft/Edge/User Data/Default",
        # Macos
        "Library/Application Support/Microsoft Edge/Default",
    ]
    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/edge/history", GENERIC_HISTORY_RECORD_FIELDS
    )
    BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/edge/download", GENERIC_DOWNLOAD_RECORD_FIELDS
    )

    @export(record=BrowserHistoryRecord)
    def history(self):
        """Return browser history records for Microsoft Edge."""
        yield from super().history("edge")

    @export(record=BrowserDownloadRecord)
    def downloads(self):
        """Return browser download records for Microsoft Edge."""
        yield from super().downloads("edge")
