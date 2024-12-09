from typing import Iterator

from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.browser.browser import (
    GENERIC_COOKIE_FIELDS,
    GENERIC_HISTORY_RECORD_FIELDS,
    BrowserPlugin,
)
from dissect.target.plugins.apps.browser.chromium import (
    ChromiumMixin,
)

class OperaPlugin(ChromiumMixin, BrowserPlugin):
    """Opera (Stable and Opera GX) browser plugin."""

    __namespace__ = "opera"

    DIRS = [
        # Windows (Stable)
        "AppData/Roaming/Opera Software/Opera Stable/Default",
        "AppData/Local/Opera Software/Opera Stable/Default",
        # Windows (GX)
        "AppData/Roaming/Opera Software/Opera GX Stable",
        "AppData/Local/Opera Software/Opera GX Stable",
        # MacOS (Stable)
        "Library/Application Support/com.operasoftware.Opera/Default",
        # MacOS (GX)
        "Library/Application Support/com.operasoftware.OperaGX",
    ]

    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/opera/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    BrowserCookieRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/opera/cookie", GENERIC_COOKIE_FIELDS
    )

    @export(record=BrowserHistoryRecord)
    def history(self) -> Iterator[BrowserHistoryRecord]:
        """Return browser history records for Opera (and Opera GX)."""
        yield from super().history("opera")

    @export(record=BrowserCookieRecord)
    def cookies(self) -> Iterator[BrowserCookieRecord]:
        """Return browser cookie records for Opera (and Opera GX)."""
        yield from super().cookies("opera")