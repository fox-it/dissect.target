import fnmatch
import re
from pathlib import Path
from typing import Iterator

from dissect.target import Target
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import arg, export
from dissect.target.plugins.general.config import (
    ConfigurationEntry,
    ConfigurationTreePlugin,
)

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
    __namespace__ = "etc"

    def __init__(self, target: Target):
        super().__init__(target, "/etc")

    def _sub(self, items: ConfigurationEntry, entry: Path, pattern: str) -> Iterator[UnixConfigTreeRecord]:
        index = 0
        config_entry = items
        if not isinstance(items, dict):
            items = items.as_dict()

        for raw_key, value in items.items():
            key = re.sub(r"[\n\r\t]", "", raw_key)
            path = Path(entry) / Path(key)

            if isinstance(value, dict):
                yield from self._sub(value, path, pattern)
                continue

            if not isinstance(value, list):
                value = [str(value)]

            if fnmatch.fnmatch(path, pattern):
                data = {
                    "_target": self.target,
                    "source": self.target.fs.path(config_entry.entry.path),
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
    @arg("--glob", dest="pattern", required=False, default="*", type=str, help="Glob-style pattern to search for")
    def etc(self, pattern: str) -> Iterator[UnixConfigTreeRecord]:
        for entry, subs, items in self.config_fs.walk("/"):
            for item in items:
                try:
                    config_object = self.get(str(Path(entry) / Path(item)))
                    if isinstance(config_object, ConfigurationEntry):
                        yield from self._sub(config_object, Path(entry) / Path(item), pattern)
                except Exception:
                    self.target.log.warning("Could not open configuration item: %s", item)
                    pass
