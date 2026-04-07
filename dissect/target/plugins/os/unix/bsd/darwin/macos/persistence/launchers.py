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

    from flow.record.base import Record

    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target

re_illegal_characters = re.compile(r"[\(\): \.\-#\/\>\<]")


class LaunchersPlugin(Plugin):
    """macOS launchers plugin."""

    SYSTEM_LAUNCH_AGENT_PATHS = (
        "/System/Library/LaunchAgents/*.plist",
        "/Library/LaunchAgents/*.plist",
    )

    SYSTEM_LAUNCH_DAEMON_PATHS = (
        "/System/Library/LaunchDaemons/*.plist",
        "/Library/LaunchDaemons/*.plist",
    )

    USER_LAUNCH_AGENT_PATHS = ("Library/LaunchAgents/*.plist",)

    USER_LAUNCH_DAEMON_PATHS = ("Library/LaunchDaemons/*.plist",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.launch_agent_files = set()
        self.launch_daemon_files = set()
        self._find_files()

    def _build_userdirs(self, hist_paths: list[str]) -> set[tuple[UserDetails, Path]]:
        """Join the selected dirs with the user home path.

        Args:
            hist_paths: A list with paths as strings.

        Returns:
            List of tuples containing user and unique file path objects.
        """
        users_dirs: set[tuple] = set()
        for user_details in self.target.user_details.all_with_home():
            for d in hist_paths:
                home_dir: Path = user_details.home_path
                for cur_dir in home_dir.glob(d):
                    cur_dir = cur_dir.resolve()
                    if cur_dir.exists():
                        users_dirs.add((user_details, cur_dir))
        return users_dirs

    def check_compatible(self) -> None:
        if not (self.launch_agent_files or self.launch_daemon_files):
            raise UnsupportedPluginError("No Agent or Deamon files found")

    def _find_files(self) -> None:
        # --- System-wide LaunchAgents ---
        for pattern in self.SYSTEM_LAUNCH_AGENT_PATHS:
            for path in self.target.fs.glob(pattern):
                self.launch_agent_files.add(path)

        # --- Per-user LaunchAgents ---
        for _, path in self._build_userdirs(self.USER_LAUNCH_AGENT_PATHS):
            self.launch_agent_files.add(path)

        # --- System-wide LaunchDaemons ---
        for pattern in self.SYSTEM_LAUNCH_DAEMON_PATHS:
            for path in self.target.fs.glob(pattern):
                self.launch_daemon_files.add(path)

        # --- Per-user LaunchDaemons ---
        for _, path in self._build_userdirs(self.USER_LAUNCH_DAEMON_PATHS):
            self.launch_daemon_files.add(path)

    @export(record=DynamicDescriptor(["string"]))
    # @export(output="yield")
    def launch_agents(self) -> Iterator[DynamicDescriptor]:
        """Yield macOS launch agent plist files."""
        for file in self.launch_agent_files:
            file = self.target.fs.path(file)
            try:
                fh = file.open(mode="rb")
            except FileNotFoundError:
                self.target.log.exception("LaunchAgent missing target: %s", {file})
                continue
            try:
                data = plistlib.load(fh)
                flat_data = {}
                extract_nested_dict(flat_data, data)

                yield self.build_record("macos/launch_agent", flat_data, file)
            except Exception:
                self.target.log.exception("Failed to parse %s", file)

    @export(record=DynamicDescriptor(["string"]))
    def launch_daemons(self) -> Iterator[DynamicDescriptor]:
        """Yield macOS launch daemon plist files."""
        for file in self.launch_daemon_files:
            file = self.target.fs.path(file)
            fh = file.open(mode="rb")
            try:
                data = plistlib.load(fh)
                flat_data = {}
                extract_nested_dict(flat_data, data)

                yield self.build_record("macos/launch_daemon", flat_data, file)
            except Exception:
                self.target.log.exception("Failed to parse %s", file)

    def build_record(self, record_name: str, rdict: dict, source: Path | None) -> Record:
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
        desc = self.create_event_descriptor(record_name, tuple(record_fields))
        return desc(**record_values)

    def create_event_descriptor(self, record_name: str, record_fields: list[tuple[str, str]]) -> TargetRecordDescriptor:
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


def extract_nested_dict(flat: dict, nested: dict) -> None:
    for k, v in nested.items():
        if isinstance(v, dict):
            extract_nested_dict(flat, v)
        else:
            flat[k] = v
