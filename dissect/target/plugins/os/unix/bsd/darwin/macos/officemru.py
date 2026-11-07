from __future__ import annotations

import json
import plistlib
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _cocoa_ts(value):
    if value and value > 0:
        try:
            return COCOA_EPOCH + timedelta(seconds=value)
        except (OSError, OverflowError, ValueError):
            return COCOA_EPOCH
    return COCOA_EPOCH


OfficeMRURecord = TargetRecordDescriptor(
    "macos/officemru/entries",
    [
        ("datetime", "ts_last_modified"),
        ("string", "document_url"),
        ("string", "application"),
        ("path", "source"),
    ],
)


class OfficeMRUPlugin(Plugin):
    """Plugin to parse Microsoft Office Most Recently Used (MRU) documents.

    Parses recently opened documents from Word, Excel, PowerPoint from:
    - AggregatedMRUSpotlightIndexedData.json (JSON format) # noqa: E501
    - *.securebookmarks.plist (plist format)
    """

    __namespace__ = "officemru"

    APP_MAP = {
        "com.microsoft.Word": "Word",
        "com.microsoft.Excel": "Excel",
        "com.microsoft.Powerpoint": "PowerPoint",
    }

    GLOBS = [
        "Users/*/Library/Containers/com.microsoft.*/Data/Library/Application Support/Microsoft/Office/*/spotlightindexer/AggregatedMRUSpotlightIndexedData.json", # noqa: E501
        "Users/*/Library/Containers/*/Data/Library/Preferences/*.securebookmarks.plist",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._paths = []
        root = self.target.fs.path("/")
        for pattern in self.GLOBS:
            self._paths.extend(root.glob(pattern))

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No Microsoft Office MRU files found")

    def _app_name(self, path):
        path_str = str(path)
        for bundle_id, name in self.APP_MAP.items():
            if bundle_id in path_str:
                return name
        for part in path_str.split("/"):
            if part.startswith("com.microsoft."):
                return part.replace("com.microsoft.", "").replace(".mac", "")
        return "Office"

    @export(record=OfficeMRURecord)
    def entries(self) -> Iterator[OfficeMRURecord]:
        """Parse Microsoft Office recently opened documents."""
        for path in self._paths:
            try:
                name = str(path).lower()
                if name.endswith(".json"):
                    yield from self._parse_json(path)
                elif name.endswith(".plist"):
                    yield from self._parse_plist(path)
            except Exception as e:
                self.target.log.warning("Error parsing %s: %s", path, e)

    def _parse_json(self, path):
        with path.open("rb") as fh:
            data = json.loads(fh.read())

        app = self._app_name(path)

        if isinstance(data, dict):
            for url, meta in data.items():
                ts = 0
                if isinstance(meta, dict):
                    ts = meta.get("lastModified", 0)
                yield OfficeMRURecord(
                    ts_last_modified=_cocoa_ts(ts),
                    document_url=url,
                    application=app,
                    source=path,
                    _target=self.target,
                )
        elif isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                yield OfficeMRURecord(
                    ts_last_modified=_cocoa_ts(item.get("lastModified", 0)),
                    document_url=item.get("identifier", item.get("url", "")),
                    application=app,
                    source=path,
                    _target=self.target,
                )

    def _parse_plist(self, path):
        with path.open("rb") as fh:
            data = plistlib.load(fh)

        app = self._app_name(path)

        if isinstance(data, dict):
            for url in data:
                yield OfficeMRURecord(
                    ts_last_modified=COCOA_EPOCH,
                    document_url=url,
                    application=app,
                    source=path,
                    _target=self.target,
                )
