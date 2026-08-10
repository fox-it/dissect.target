from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import arg, export
from dissect.target.plugins.apps.browser.browser import (
    GENERIC_CACHE_FIELDS,
    GENERIC_COOKIE_FIELDS,
    GENERIC_DOWNLOAD_RECORD_FIELDS,
    GENERIC_EXTENSION_RECORD_FIELDS,
    GENERIC_HISTORY_RECORD_FIELDS,
    GENERIC_PASSWORD_RECORD_FIELDS,
    BrowserPlugin,
)
from dissect.target.plugins.apps.browser.chromium import (
    CHROMIUM_DOWNLOAD_RECORD_FIELDS,
    ChromiumMixin,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


class BravePlugin(ChromiumMixin, BrowserPlugin):
    """Brave browser plugin."""

    __namespace__ = "brave"

    DIRS = (
        # Windows
        "AppData/Local/BraveSoftware/Brave-Browser/User Data/Default",
        "AppData/Local/BraveSoftware/Brave-Browser/User Data/Profile*",
        "AppData/Roaming/BraveSoftware/Brave-Browser/User Data/Default",
        "AppData/Roaming/BraveSoftware/Brave-Browser/User Data/Profile*",
        # Linux
        ".config/BraveSoftware/Default",
        ".config/BraveSoftware/Profile*",
        ".config/BraveSoftware/Brave-Browser/Default",
        ".config/BraveSoftware/Brave-Browser/Profile*",
        "snap/brave/*/.config/BraveSoftware/Brave-Browser/Default",
        "snap/brave/*/.config/BraveSoftware/Brave-Browser/Profile*",
        # Macos
        "Library/Application Support/BraveSoftware/Default",
        "Library/Application Support/BraveSoftware/Brave-Browser/Default",
        "Library/Application Support/BraveSoftware/Profile*",
        "Library/Application Support/BraveSoftware/Brave-Browser/Profile*",
    )

    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/brave/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    BrowserCookieRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/brave/cookie", GENERIC_COOKIE_FIELDS
    )

    BrowserCacheRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/brave/cache",
        GENERIC_CACHE_FIELDS,
    )

    BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/brave/download", GENERIC_DOWNLOAD_RECORD_FIELDS + CHROMIUM_DOWNLOAD_RECORD_FIELDS
    )

    BrowserExtensionRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/brave/extension", GENERIC_EXTENSION_RECORD_FIELDS
    )

    BrowserPasswordRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/brave/password", GENERIC_PASSWORD_RECORD_FIELDS
    )

    @export(record=BrowserHistoryRecord)
    def history(self) -> Iterator[BrowserHistoryRecord]:
        """Return browser history records for Brave."""
        yield from super().history("brave")

    @export(record=BrowserCookieRecord)
    def cookies(self) -> Iterator[BrowserCookieRecord]:
        """Return browser cookie records for Brave."""
        yield from super().cookies("brave")

    @export(record=BrowserCacheRecord)
    @arg("--export", type=Path, help="export cache files to provided directory")
    def cache(self, export: Path | None = None) -> Iterator[BrowserCacheRecord]:
        """Return browser cache records for Brave."""
        yield from super().cache("brave", export)

    @export(record=BrowserDownloadRecord)
    def downloads(self) -> Iterator[BrowserDownloadRecord]:
        """Return browser download records for Brave."""
        yield from super().downloads("brave")

    @export(record=BrowserExtensionRecord)
    def extensions(self) -> Iterator[BrowserExtensionRecord]:
        """Return browser extension records for Brave."""
        yield from super().extensions("brave")

    @export(record=BrowserPasswordRecord)
    def passwords(self) -> Iterator[BrowserPasswordRecord]:
        """Return browser password records for Brave."""
        yield from super().passwords("brave")
