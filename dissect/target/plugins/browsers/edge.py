from dissect.target import Target
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import GENERIC_HISTORY_RECORD_FIELDS
from dissect.target.plugins.browsers.chromiummixin import ChromiumMixin

EdgeBrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browser/edge/history", GENERIC_HISTORY_RECORD_FIELDS
)


class EdgePlugin(ChromiumMixin, Plugin):
    """Edge browser plugin.

    Yields: EdgeBrowserHistoryRecord
    """

    __namespace__ = "edge"

    DIRS: list = [
        # Windows
        "AppData/Local/Microsoft/Edge/User Data/Default",
        # Macos
        "Library/Application Support/Microsoft Edge/Default",
    ]
    HISTORY_RECORD = EdgeBrowserHistoryRecord

    def __init__(self, target: Target):
        super().__init__(target)

    def check_compatible(self):
        """Perform a compatibility check with the target."""
        ChromiumMixin.check_compatible(self)

    @export(record=HISTORY_RECORD)
    def history(self):
        """Return browser history records for Microsoft Edge."""
        yield from ChromiumMixin.history(self, "edge")
