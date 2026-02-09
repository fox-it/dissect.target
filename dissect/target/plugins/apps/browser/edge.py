from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.browser.browser import (
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


class EdgePlugin(ChromiumMixin, BrowserPlugin):
    """Edge browser plugin."""

    __namespace__ = "edge"

    DIRS = (
        # Linux
        ".config/microsoft-edge/Default/",
        ".config/microsoft-edge/Profile*",
        ".var/app/com.microsoft.Edge/config/microsoft-edge/Default",
        ".var/app/com.microsoft.Edge/config/microsoft-edge/Profile*",
        # Windows
        "AppData/Local/Microsoft/Edge/User Data/Default",
        "AppData/Local/Microsoft/Edge/User Data/Profile*",
        "AppData/Local/Microsoft/Edge/User Data/Snapshots/*/Default",
        "AppData/Local/Microsoft/Edge/User Data/Snapshots/*/Profile*",
        # Macos
        "Library/Application Support/Microsoft Edge/Default",
        "Library/Application Support/Microsoft Edge/Profile*",
    )

    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/edge/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    BrowserCookieRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/edge/cookie", GENERIC_COOKIE_FIELDS
    )

    BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/edge/download", GENERIC_DOWNLOAD_RECORD_FIELDS + CHROMIUM_DOWNLOAD_RECORD_FIELDS
    )

    BrowserExtensionRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/edge/extension", GENERIC_EXTENSION_RECORD_FIELDS
    )

    BrowserPasswordRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/edge/password", GENERIC_PASSWORD_RECORD_FIELDS
    )

    @export(record=BrowserHistoryRecord)
    def history(self) -> Iterator[BrowserHistoryRecord]:
        """Return browser history records for Microsoft Edge."""
        yield from super().history("edge")

    @export(record=BrowserCookieRecord)
    def cookies(self) -> Iterator[BrowserCookieRecord]:
        """Return browser cookie records for Microsoft Edge."""
        yield from super().cookies("edge")

    @export(record=BrowserDownloadRecord)
    def downloads(self) -> Iterator[BrowserDownloadRecord]:
        """Return browser download records for Microsoft Edge."""
        yield from super().downloads("edge")

    @export(record=BrowserExtensionRecord)
    def extensions(self) -> Iterator[BrowserExtensionRecord]:
        """Return browser extension records for Microsoft Edge."""
        yield from super().extensions("edge")

    @export(record=BrowserPasswordRecord)
    def passwords(self) -> Iterator[BrowserPasswordRecord]:
        """Return browser password records for Microsoft Edge."""
        yield from super().passwords("edge")
