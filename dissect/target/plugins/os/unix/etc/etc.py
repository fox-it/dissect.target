from __future__ import annotations

import fnmatch
import re
from typing import TYPE_CHECKING

from dissect.target.helpers import configutil
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath

UnixConfigTreeRecord = TargetRecordDescriptor(
    "unix/config",
    [
        ("path", "source"),
        ("path", "config_path"),
        ("string", "key"),
        ("string[]", "value"),
    ],
)


class EtcTree(Plugin):
    """Unix etc configuration tree plugin."""

    __namespace__ = "etc"

    def check_compatible(self) -> None:
        return None

    def _sub(
        self, items: configutil.ConfigurationParser, entry: TargetPath, orig_path: TargetPath, pattern: str
    ) -> Iterator[UnixConfigTreeRecord]:
        index = 0

        for raw_key, value in items.items():
            key = re.sub(r"[\n\r\t/]", "", raw_key)
            path = entry / key

            if isinstance(value, dict):
                yield from self._sub(value, path, orig_path, pattern)
                continue

            if not isinstance(value, list):
                value = [str(value)]

            if fnmatch.fnmatch(path, pattern):
                config_path = entry.relative_to(orig_path)
                data = {
                    "_target": self.target,
                    "source": orig_path,
                    "config_path": "/" / config_path,
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
    @arg("--root", dest="root", default="/etc", help="Path to use as root for search")
    @arg("--unknowns", dest="unknowns", action="store_true", help="Return unknown / unparsable objects")
    def etc(self, pattern: str, root: str, unknowns: bool) -> Iterator[UnixConfigTreeRecord]:
        """This plugin yields configuration information from the etc directory in key value pairs.

        Args:
            pattern: What Glob-style pattern to search for
            root: Path to use as root for searching
            unknowns: Whether to also yield entries for unknown entries.

        Yields UnixConfigTreeRecord with the following fields:

        .. code-block:: text

            source (path): The path on the target used for parsing.
            config_path (path): The path inside the configuration file that is being used.
            key (string): The configuration key returned by parsing.
            value (string[]): The configuration value belonging to the key.
        """

        for entry, _, items in self.target.fs.walk(root):
            for item in items:
                path = self.target.fs.path(entry) / item
                try:
                    config_object = configutil.parse(self.target.fs.path(path))

                    if not unknowns and isinstance(config_object, (configutil.Txt, configutil.Bin)):
                        # We don't have a specific config parser for this file,
                        # Ignore those config paths to get proper records
                        continue
                    yield from self._sub(config_object, path, orig_path=path, pattern=pattern)
                except Exception:
                    self.target.log.warning("Could not parse file: %s", path)
