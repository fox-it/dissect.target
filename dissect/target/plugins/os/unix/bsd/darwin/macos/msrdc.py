from __future__ import annotations

import json
import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


MsrdcConnectionRecord = TargetRecordDescriptor(
    "macos/msrdc/connections",
    [
        ("string", "remote_host"),
        ("string", "friendly_name"),
        ("string", "username"),
        ("path", "source"),
    ],
)


class MacOSMsrdcPlugin(Plugin):
    """Plugin to parse Microsoft Remote Desktop connection bookmarks on macOS.

    Locations:
        ~/Library/Containers/com.microsoft.rdc.macos/.../com.microsoft.rdc.macos/*.json
        ~/Library/Containers/com.microsoft.rdc.macos/.../application-data/bookmarks/*.json
        ~/Library/Group Containers/*.com.microsoft.rdc.macos/*/bookmarks.plist
    """

    __namespace__ = "msrdc"

    JSON_GLOBS = [
        "Users/*/Library/Containers/com.microsoft.rdc.macos/Data/Library/Application Support/com.microsoft.rdc.macos/*.json", # noqa: E501
        "Users/*/Library/Containers/com.microsoft.rdc.macos/Data/Library/Application Support/com.microsoft.rdc.macos/com.microsoft.rdc.application-data/bookmarks/*.json", # noqa: E501
    ]

    PLIST_GLOBS = [
        "Users/*/Library/Group Containers/*.com.microsoft.rdc.macos/*/bookmarks.plist",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._json_paths = []
        self._plist_paths = []
        root = self.target.fs.path("/")

        for pattern in self.JSON_GLOBS:
            self._json_paths.extend(root.glob(pattern))

        for pattern in self.PLIST_GLOBS:
            self._plist_paths.extend(root.glob(pattern))

    def check_compatible(self) -> None:
        if not self._json_paths and not self._plist_paths:
            raise UnsupportedPluginError("No Microsoft Remote Desktop bookmarks found")

    def _extract_connection(self, data):
        """Extract hostname, friendly_name, username from a dict."""
        hostname = ""
        friendly_name = ""
        username = ""

        if isinstance(data, dict):
            # Common JSON keys
            for key in ["hostName", "hostname", "host_name", "PCName", "pc_name", "HostName"]:
                if key in data and data[key]:
                    hostname = str(data[key])
                    break

            for key in ["friendlyName", "friendly_name", "FriendlyName", "label", "name", "Name"]:
                if key in data and data[key]:
                    friendly_name = str(data[key])
                    break

            for key in ["userName", "username", "user_name", "UserName"]:
                if key in data and data[key]:
                    username = str(data[key])
                    break

            # Check nested credential
            cred = data.get("credential") or data.get("credentials") or {}
            if isinstance(cred, dict) and not username:
                for key in ["userName", "username", "UserName"]:
                    if key in cred and cred[key]:
                        username = str(cred[key])
                        break

        return hostname, friendly_name, username

    @export(record=MsrdcConnectionRecord)
    def connections(self) -> Iterator[MsrdcConnectionRecord]:
        """Parse Microsoft Remote Desktop connection bookmarks."""
        for path in self._json_paths:
            try:
                with path.open("r") as fh:
                    data = json.loads(fh.read())

                if isinstance(data, list):
                    for item in data:
                        hostname, friendly_name, username = self._extract_connection(item)
                        if hostname or friendly_name:
                            yield MsrdcConnectionRecord(
                                remote_host=hostname,
                                friendly_name=friendly_name,
                                username=username,
                                source=path,
                                _target=self.target,
                            )
                elif isinstance(data, dict):
                    # Could be a single bookmark or a container with bookmarks
                    bookmarks = data.get("bookmarks", data.get("connections", None))
                    if isinstance(bookmarks, list):
                        for item in bookmarks:
                            hostname, friendly_name, username = self._extract_connection(item)
                            if hostname or friendly_name:
                                yield MsrdcConnectionRecord(
                                    hostname=hostname,
                                    friendly_name=friendly_name,
                                    username=username,
                                    source=path,
                                    _target=self.target,
                                )
                    else:
                        hostname, friendly_name, username = self._extract_connection(data)
                        if hostname or friendly_name:
                            yield MsrdcConnectionRecord(
                                remote_host=hostname,
                                friendly_name=friendly_name,
                                username=username,
                                source=path,
                                _target=self.target,
                            )
            except Exception as e:
                self.target.log.warning("Error parsing MSRDC JSON %s: %s", path, e)

        for path in self._plist_paths:
            try:
                with path.open("rb") as fh:
                    data = plistlib.loads(fh.read())

                items = data if isinstance(data, list) else data.get("bookmarks", [data])
                if not isinstance(items, list):
                    items = [items]

                for item in items:
                    hostname, friendly_name, username = self._extract_connection(item)
                    if hostname or friendly_name:
                        yield MsrdcConnectionRecord(
                            hostname=hostname,
                            friendly_name=friendly_name,
                            username=username,
                            source=path,
                            _target=self.target,
                        )
            except Exception as e:
                self.target.log.warning("Error parsing MSRDC plist %s: %s", path, e)
