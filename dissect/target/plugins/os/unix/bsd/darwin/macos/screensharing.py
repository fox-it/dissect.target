from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


ScreenSharingRecord = TargetRecordDescriptor(
    "macos/screensharing/connections",
    [
        ("string", "remote_host"),
        ("string", "display_name"),
        ("string", "connection_type"),
        ("path", "source"),
    ],
)


class ScreenSharingPlugin(Plugin):
    """Plugin to parse macOS Screen Sharing connection history.

    Parses recent screen sharing connections from the ScreenSharing preferences plist.

    Location: ~/Library/Containers/com.apple.ScreenSharing/Data/Library/Preferences/com.apple.ScreenSharing.plist
    """

    __namespace__ = "screensharing"

    PLIST_GLOB = (
        "Users/*/Library/Containers/com.apple.ScreenSharing/Data/Library/Preferences/com.apple.ScreenSharing.plist"
    )

    def __init__(self, target):
        super().__init__(target)
        self._plist_paths = list(self.target.fs.path("/").glob(self.PLIST_GLOB))

    def check_compatible(self) -> None:
        if not self._plist_paths:
            raise UnsupportedPluginError("No ScreenSharing plist found")

    @export(record=ScreenSharingRecord)
    def connections(self) -> Iterator[ScreenSharingRecord]:
        """Parse Screen Sharing connection history."""
        for plist_path in self._plist_paths:
            try:
                yield from self._parse_plist(plist_path)
            except Exception as e:
                self.target.log.warning("Error parsing ScreenSharing at %s: %s", plist_path, e)

    def _parse_plist(self, plist_path):
        with plist_path.open("rb") as fh:
            data = plistlib.loads(fh.read())

        # Parse recent hosts from various known keys
        recent_hosts = data.get("NSNavRecentPlaces", [])
        if isinstance(recent_hosts, list):
            for host in recent_hosts:
                yield ScreenSharingRecord(
                    remote_host=str(host),
                    display_name="",
                    connection_type="recent",
                    source=plist_path,
                    _target=self.target,
                )

        # Parse saved connections
        for key in ["savedConnections", "RecentHosts", "RecentServers"]:
            entries = data.get(key, [])
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        yield ScreenSharingRecord(
                            remote_host=entry.get("hostname", entry.get("host", str(entry))),
                            display_name=entry.get("displayName", entry.get("name", "")),
                            connection_type=key,
                            source=plist_path,
                            _target=self.target,
                        )
                    elif isinstance(entry, str):
                        yield ScreenSharingRecord(
                            remote_host=entry,
                            display_name="",
                            connection_type=key,
                            source=plist_path,
                            _target=self.target,
                        )
            elif isinstance(entries, dict):
                for host, info in entries.items():
                    yield ScreenSharingRecord(
                        remote_host=str(host),
                        display_name=str(info) if not isinstance(info, dict) else info.get("displayName", ""),
                        connection_type=key,
                        source=plist_path,
                        _target=self.target,
                    )
