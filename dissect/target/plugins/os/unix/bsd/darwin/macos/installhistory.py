from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


InstallHistoryRecord = TargetRecordDescriptor(
    "macos/install_history",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("string", "version"),
        ("string", "process"),
        ("string", "content_type"),
        ("stringlist", "package_ids"),
        ("path", "source"),
    ],
)


class InstallHistoryPlugin(Plugin):
    """macOS install history plugin."""

    PATH = "/Library/Receipts/InstallHistory.plist"

    def check_compatible(self) -> None:
        if not self.target.fs.path(self.PATH).exists():
            raise UnsupportedPluginError("No InstallHistory.plist found")

    @export(record=InstallHistoryRecord)
    def install_history(self) -> Iterator[InstallHistoryRecord]:
        """Yield software install events recorded by the macOS installer.

        macOS writes a record to ``/Library/Receipts/InstallHistory.plist`` whenever the
        installer daemon (``installd``/``softwareupdated``) completes an install, operating
        system update, or configuration data delivery (XProtect, MRT, Gatekeeper).

        Yields ``InstallHistoryRecord`` with the following fields:

        .. code-block:: text

            ts (datetime): Install timestamp.
            name (string): Display name of the installed item.
            version (string): Display version of the installed item.
            process (string): Name of the process that performed the install.
            content_type (string): Content type, e.g. ``config-data`` for XProtect/MRT payloads.
            package_ids (stringlist): Package identifiers included in the install.
            source (path): The source plist of the install history record.
        """
        source = self.target.fs.path(self.PATH)
        with source.open("rb") as fh:
            entries = plistlib.load(fh)

        for entry in entries:
            yield InstallHistoryRecord(
                ts=entry.get("date"),
                name=entry.get("displayName"),
                version=entry.get("displayVersion"),
                process=entry.get("processName"),
                content_type=entry.get("contentType"),
                package_ids=entry.get("packageIdentifiers") or [],
                source=source,
                _target=self.target,
            )
