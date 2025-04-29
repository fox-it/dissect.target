from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import arg, export
from dissect.target.plugins.general.config import (
    ConfigurationEntry,
    ConfigurationTreePlugin,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

UnixConfigTreeRecord = TargetRecordDescriptor(
    "unix/config",
    [
        ("path", "source"),
        ("path", "path"),
        ("string", "key"),
        ("string[]", "value"),
    ],
)


class EtcTree(ConfigurationTreePlugin):
    """Unix etc configuration tree plugin."""

    __namespace__ = "etc"

    def __init__(self, target: Target):
        super().__init__(target, "/etc")

    def _sub(
        self, items: ConfigurationEntry | dict, entry: Path, orig_path: Path, pattern: str
    ) -> Iterator[UnixConfigTreeRecord]:
        index = 0
        if not isinstance(items, dict):
            items = items.as_dict()

        for raw_key, value in items.items():
            key = re.sub(r"[\n\r\t]", "", raw_key)
            path = Path(entry) / Path(key)

            if isinstance(value, dict):
                yield from self._sub(value, path, orig_path, pattern)
                continue

            if not isinstance(value, list):
                value = [str(value)]

            if fnmatch.fnmatch(path, pattern):
                data = {
                    "_target": self.target,
                    "source": self.target.fs.path(orig_path),
                    "path": path,
                    "key": key,
                    "value": value,
                }
                if value == [""]:
                    data["key"] = index
                    data["value"] = [key]
                    index += 1

                yield UnixConfigTreeRecord(**data)

    @export(record=UnixConfigTreeRecord)
    @arg("--glob", dest="pattern", default="*", help="Glob-style pattern to search for")
    @arg("--root", dest="root", default="/", help="Path to use as root for search")
    def etc(self, pattern: str, root: str) -> Iterator[UnixConfigTreeRecord]:
        """Yield etc configuration records."""

        for entry, _, items in self.config_fs.walk(root):
            for item in items:
                try:
                    path = Path(entry) / item
                    config_object = self.get(str(path))

                    if isinstance(config_object, ConfigurationEntry):
                        yield from self._sub(config_object, path, orig_path=path, pattern=pattern)
                except Exception:  # noqa: PERF203
                    self.target.log.warning("Could not open configuration item: %s", item)
