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
from dissect.util.ts import webkittimestamp

if TYPE_CHECKING:
    from collections.abc import Iterator


OPERA_EXTENSION_RECORD_FIELDS = [
    ("boolean", "blacklisted"),
]


class OperaPlugin(ChromiumMixin, BrowserPlugin):
    """Opera (Stable and Opera GX) browser plugin."""

    __namespace__ = "opera"

    DIRS = [
        # Windows (Stable)
        "AppData/Roaming/Opera Software/Opera Stable/Default",
        "AppData/Local/Opera Software/Opera Stable/Default",
        # Windows (GX)
        "AppData/Roaming/Opera Software/Opera GX Stable/Default",
        "AppData/Local/Opera Software/Opera GX Stable/Default",
        # MacOS (Stable)
        "Library/Application Support/com.operasoftware.Opera/Default",
        # MacOS (GX)
        "Library/Application Support/com.operasoftware.OperaGX/Default",
    ]

    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/opera/history",
        GENERIC_HISTORY_RECORD_FIELDS,
    )

    BrowserCookieRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/opera/cookie",
        GENERIC_COOKIE_FIELDS,
    )

    BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/opera/download",
        GENERIC_DOWNLOAD_RECORD_FIELDS + CHROMIUM_DOWNLOAD_RECORD_FIELDS,
    )

    BrowserExtensionRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/opera/extension",
        GENERIC_EXTENSION_RECORD_FIELDS + OPERA_EXTENSION_RECORD_FIELDS,
    )

    BrowserPasswordRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "application/browser/opera/password",
        GENERIC_PASSWORD_RECORD_FIELDS,
    )

    @export(record=BrowserHistoryRecord)
    def history(self) -> Iterator[BrowserHistoryRecord]:
        """Return browser history records for Opera (and Opera GX)."""
        yield from super().history("opera")

    @export(record=BrowserCookieRecord)
    def cookies(self) -> Iterator[BrowserCookieRecord]:
        """Return browser cookie records for Opera (and Opera GX)."""
        yield from super().cookies("opera")

    @export(record=BrowserDownloadRecord)
    def downloads(self) -> Iterator[BrowserDownloadRecord]:
        """Return browser download records for Opera (and Opera GX)."""
        yield from super().downloads("opera")

    @export(record=BrowserExtensionRecord)
    def extensions(self) -> Iterator[BrowserExtensionRecord]:
        """Iterates over all installed extensions for Opera (and Opera GX).

        Yields:

        .. code-block:: text

            Records with the following fields:
                blacklisted (boolean): Extension blacklisted by Opera/Opera GX.
                ts_install (datetime): Extension install timestamp.
                ts_update (datetime): Extension update timestamp.
                browser (string): The browser from which the records are generated.
                id (string): Extension unique identifier.
                name (string): Name of the extension.
                short_name (string): Short name of the extension.
                default_title (string): Default title of the extension.
                description (string): Description of the extension.
                version (string): Version of the extension.
                ext_path (path): Relative path of the extension.
                from_webstore (boolean): Extension from webstore.
                permissions (string[]): Permissions of the extension.
                manifest (varint): Version of the extensions' manifest.
                source: (path): The source file of the download record.
        """
        for user, json_file, content in self._iter_json("Secure Preferences"):
            try:
                extensions = content.get("extensions").get("opsettings")
                for extension_id, extension_data in extensions.items():

                    # Opera includes a bunch of empty (prefilled) blacklisted extensions with only one key called
                    # 'blacklist_state'. If no other metadata is present, it's not installed. Filtering based on if
                    # the extension itself is blacklisted is a no-go as you can still install blacklisted extensions.
                    blacklisted = bool(
                        extension_data.get("blacklist_state", 0)
                    )
                    if blacklisted and len(extension_data.keys()) == 1:
                        continue

                    ts_install = extension_data.get(
                        "first_install_time") or extension_data.get("install_time")
                    ts_update = extension_data.get("last_update_time")

                    if ts_install:
                        ts_install = webkittimestamp(ts_install)
                    if ts_update:
                        ts_update = webkittimestamp(ts_update)

                    if ext_path := extension_data.get("path"):
                        ext_path = self.target.fs.path(ext_path)

                    manifest = extension_data.get("manifest")
                    if manifest:
                        name = manifest.get("name")
                        short_name = manifest.get("short_name")
                        description = manifest.get("description")
                        ext_version = manifest.get("version")
                        ext_permissions = manifest.get("permissions")
                        manifest_version = manifest.get("manifest_version")

                        if manifest.get("browser_action"):
                            default_title = manifest.get(
                                "browser_action").get("default_title")
                        else:
                            default_title = None

                    else:
                        name = None
                        short_name = None
                        default_title = None
                        description = None
                        ext_version = None
                        ext_permissions = None
                        manifest_version = None

                    yield self.BrowserExtensionRecord(
                        blacklisted=blacklisted,
                        ts_install=ts_install,
                        ts_update=ts_update,
                        browser=self.__namespace__,
                        extension_id=extension_id,
                        name=name,
                        short_name=short_name,
                        default_title=default_title,
                        description=description,
                        version=ext_version,
                        ext_path=ext_path,
                        from_webstore=extensions.get(
                            extension_id).get("from_webstore"),
                        permissions=ext_permissions,
                        manifest_version=manifest_version,
                        source=json_file,
                        _target=self.target,
                        _user=user.user,
                    )
            except (AttributeError, KeyError) as e:  # noqa: PERF203
                self.target.log.warning(
                    "No browser extensions found in: %s", json_file)
                self.target.log.debug("", exc_info=e)

    @export(record=BrowserPasswordRecord)
    def passwords(self) -> Iterator[BrowserPasswordRecord]:
        """Return browser password records for Opera (and Opera GX)."""
        yield from super().passwords("opera")
