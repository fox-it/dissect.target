from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import GENERIC_HISTORY_RECORD_FIELDS
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
    HISTORY_RECORD = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/edge/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    @export(record=HISTORY_RECORD)
    def history(self):
        """Return browser history records for Microsoft Edge."""
        yield from ChromiumMixin.history(self, "edge")
