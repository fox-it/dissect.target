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


class ChromePlugin(ChromiumMixin, BrowserPlugin):
    """Chrome browser plugin."""

    __namespace__ = "chrome"

    DIRS = (
        # Windows
        "AppData/Local/Google/Chrome/User Data/Default",
        "AppData/Local/Google/Chrome/User Data/Profile*",
        "AppData/Local/Google/Chrome/User Data/Snapshots/*/Default",
        "AppData/Local/Google/Chrome/User Data/Snapshots/*/Profile*",
        "AppData/Local/Google/Chrome/continuousUpdates/User Data/Default",
        "AppData/Local/Google/Chrome/continuousUpdates/User Data/Profile*",
        "Local Settings/Application Data/Google/Chrome/User Data/Default",
        "Local Settings/Application Data/Google/Chrome/User Data/Profile*",
        # Linux
        ".config/google-chrome/Default",
        ".config/google-chrome/Profile*",
        ".var/app/com.google.Chrome/config/google-chrome/Default",
        ".var/app/com.google.Chrome/config/google-chrome/Profile*",
        # Macos
        "Library/Application Support/Google/Chrome/Default",
        "Library/Application Support/Google/Chrome/Profile*",
    )

    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/chrome/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    BrowserCookieRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/chrome/cookie", GENERIC_COOKIE_FIELDS
    )

    BrowserCacheRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/chrome/cache",
        GENERIC_CACHE_FIELDS,
    )

    BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/chrome/download", GENERIC_DOWNLOAD_RECORD_FIELDS + CHROMIUM_DOWNLOAD_RECORD_FIELDS
    )

    BrowserExtensionRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/chrome/extension", GENERIC_EXTENSION_RECORD_FIELDS
    )

    BrowserPasswordRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/chrome/password", GENERIC_PASSWORD_RECORD_FIELDS
    )

    @export(record=BrowserHistoryRecord)
    def history(self) -> Iterator[BrowserHistoryRecord]:
        """Return browser history records for Google Chrome."""
        yield from super().history("chrome")

    @export(record=BrowserCookieRecord)
    def cookies(self) -> Iterator[BrowserCookieRecord]:
        """Return browser cookie records for Google Chrome."""
        yield from super().cookies("chrome")

    @export(record=BrowserCacheRecord)
    @arg("--export", type=Path, help="export cache files to provided directory")
    def cache(self, export: Path | None = None) -> Iterator[BrowserCacheRecord]:
        """Return browser cache records for Microsoft Edge."""
        yield from super().cache("chrome", export)

    @export(record=BrowserDownloadRecord)
    def downloads(self) -> Iterator[BrowserDownloadRecord]:
        """Return browser download records for Google Chrome."""
        yield from super().downloads("chrome")

    @export(record=BrowserExtensionRecord)
    def extensions(self) -> Iterator[BrowserExtensionRecord]:
        """Return browser extension records for Google Chrome."""
        yield from super().extensions("chrome")

    @export(record=BrowserPasswordRecord)
    def passwords(self) -> Iterator[BrowserPasswordRecord]:
        """Return browser password records for Google Chrome."""
        yield from super().passwords("chrome")
