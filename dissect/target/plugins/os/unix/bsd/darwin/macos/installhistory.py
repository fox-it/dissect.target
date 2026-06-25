from __future__ import annotations

import plistlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


InstallHistoryRecord = TargetRecordDescriptor(
    "macos/installhistory/entries",
    [
        ("datetime", "ts"),
        ("string", "display_name"),
        ("string", "display_version"),
        ("string", "process_name"),
        ("string", "content_type"),
        ("string[]", "package_identifiers"),
        ("path", "source"),
    ],
)


class InstallHistoryPlugin(Plugin):
    """Plugin to parse macOS InstallHistory.plist.

    Parses the system-wide installation history log at:
    /Library/Receipts/InstallHistory.plist

    Records every software installation, update, and config-data push
    including macOS updates, XProtect, Gatekeeper, MRT, and third-party apps.
    """

    __namespace__ = "installhistory"

    INSTALL_HISTORY_PATHS = [
        "Library/Receipts/InstallHistory.plist",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._paths = []
        root = self.target.fs.path("/")
        for p in self.INSTALL_HISTORY_PATHS:
            path = root.joinpath(p)
            if path.exists():
                self._paths.append(path)

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No InstallHistory.plist found")

    @export(record=InstallHistoryRecord)
    def entries(self) -> Iterator[InstallHistoryRecord]:
        """Parse software installation history from InstallHistory.plist."""
        for path in self._paths:
            try:
                with path.open("rb") as fh:
                    data = plistlib.loads(fh.read())

                if not isinstance(data, list):
                    continue

                for entry in data:
                    ts = entry.get("date")
                    if isinstance(ts, datetime):
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                    else:
                        ts = datetime(1970, 1, 1, tzinfo=timezone.utc)

                    yield InstallHistoryRecord(
                        ts=ts,
                        display_name=entry.get("displayName", ""),
                        display_version=entry.get("displayVersion", ""),
                        process_name=entry.get("processName", ""),
                        content_type=entry.get("contentType", ""),
                        package_identifiers=entry.get("packageIdentifiers", []),
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s: %s", path, e)
