from __future__ import annotations

import plistlib
import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target
    from flow.record.base import Record

re_illegal_characters = re.compile(r"[\(\): \.\-#\/\>\<]")

class UserPlugin(Plugin):
    """macOS user plugin."""

    LAUNCH_AGENT_PATHS = [
        "/System/Library/LaunchAgents/*.plist",
        "/Library/LaunchAgents/*.plist",
        "~/Library/LaunchAgents/*.plist",
    ]
    LAUNCH_DAEMON_PATHS = [
        "/System/Library/LaunchDaemons/*.plist",
        "/Library/LaunchDaemons/*.plist",
    ]
    LAUNCH_AGENT_FILES = set()
    LAUNCH_DAEMON_FILES = set()

    def __init__(self, target: Target):
        super().__init__(target)
        self._find_files()

    def check_compatible(self) -> None:
        if not (self.LAUNCH_AGENT_FILES or self.LAUNCH_DAEMON_FILES):
            raise UnsupportedPluginError("No Agent or Deamon files found")

    def _find_files(self):
        for glob in self.LAUNCH_AGENT_PATHS:
            for path in self.target.fs.glob(glob):
                self.LAUNCH_AGENT_FILES.add(path)

        for glob in self.LAUNCH_DAEMON_PATHS:
            for path in self.target.fs.glob(glob):
                self.LAUNCH_DAEMON_FILES.add(path)


    @export(record=DynamicDescriptor(["string"]))
    # @export(output="yield")
    def launch_agents(self) -> Iterator[DynamicDescriptor]:
        """Yield OS X launch agent plist files."""

        for file in self.LAUNCH_AGENT_FILES:
            file = self.target.fs.path(file)
            fh = file.open(mode="rb")
            try:
                data = plistlib.load(fh)
                flat_data = {}
                extract_nested_dict(flat_data, data)

                yield self._build_record("osx/launch_agent", flat_data, file)
            except Exception:
                self.target.log.exception("Failed to parse %s", file)

    @export(record=DynamicDescriptor(["string"]))
    def launch_daemons(self) -> Iterator[DynamicDescriptor]:
        """Yield OS X launch daemon plist files."""

        for file in self.LAUNCH_DAEMON_FILES:
            file = self.target.fs.path(file)
            fh = file.open(mode="rb")
            try:
                data = plistlib.load(fh)
                flat_data = {}
                extract_nested_dict(flat_data, data)

                yield self._build_record("osx/launch_daemon", flat_data, file)
            except Exception:
                self.target.log.exception("Failed to parse %s", file)

    def _build_record(self, record_name: str, rdict: dict, source: Path | None) -> Record:
            # predictable order of fields in the list is important, since we'll
            # be constructing a record descriptor from it.
            record_fields = sorted(rdict.items())

            record_values = {
                "_target": self.target,
                "source": source,
            }
            record_fields = []

            for k, v in rdict.items():
                k = format_key(k)

                if isinstance(v, bool):
                    record_fields.append(("boolean", k))
                elif isinstance(v, int):
                    record_fields.append(("varint", k))
                else:
                    record_fields.append(("string", k))

                record_values[k] = v

            record_fields.append(("path", "source"))

            # tuple conversion here is needed for lru_cache
            desc = self._create_event_descriptor(record_name, tuple(record_fields))
            return desc(**record_values)

    def _create_event_descriptor(self, record_name, record_fields: list[tuple[str, str]]) -> TargetRecordDescriptor:
        return TargetRecordDescriptor(record_name, record_fields)

def format_key(key: str) -> str:
    # A lot of "malformed" keys
    key = key.replace(".", "_")
    key = key.replace("-", "_")
    key = key.replace("@", "_")
    key = key.replace(" ", "_")
    key = key.replace("()", "")
    key = key.removeprefix("#")
    key = key.removeprefix("_")
    key = key.lstrip("_")

    if "/" in key:
        key = key.rsplit("/", 1)[-1]

    if key == "0":
        key = "zero"

    return key


def extract_nested_dict(flat, nested):
    for k, v in nested.items():
        if isinstance(v, dict):
                extract_nested_dict(flat, v)
        else:
            flat[k] = v

