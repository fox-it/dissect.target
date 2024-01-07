from __future__ import annotations

from enum import Enum
from typing import Iterator

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

PackageManagerLogRecord = TargetRecordDescriptor(
    "unix/log/packagemanager",
    [
        ("datetime", "ts"),
        ("string", "package_manager"),
        ("string", "operation"),
        ("string", "package_name"),
        ("string", "command"),
        ("string", "requested_by_user"),
    ],
)


class OperationTypes(Enum):
    Install = "install"
    Update = "update"
    Downgrade = "downgrade"
    Remove = "remove"
    Other = "other"

    __MAPPING__: dict = {
        Install: ["install", "installed", "reinstall"],
        Update: ["update", "updated", "upgrade"],
        Downgrade: ["downgrade"],
        Remove: ["remove", "removed", "erased", "purge"],
        Other: ["command"],
    }

    @classmethod
    def infer(cls, keyword: str) -> OperationTypes:
        keyword = keyword.strip().lower()
        for key, values in cls.__MAPPING__.items():
            if keyword in values:
                return OperationTypes(key)
        return OperationTypes.Other


class PackageManagerPlugin(Plugin):
    __namespace__ = "packagemanager"
    __findable__ = False

    TOOLS = [
        "apt",
        "yum",
        "zypper",
    ]

    def __init__(self, target: Target):
        super().__init__(target)
        self._plugins = []
        for entry in self.TOOLS:
            try:
                self._plugins.append(getattr(self.target, entry))
            except Exception:
                target.log.exception(f"Failed to load tool plugin: {entry}")

    def check_compatible(self) -> None:
        if not len(self._plugins):
            raise UnsupportedPluginError("No compatible plugins found")

    def _func(self, f: str) -> Iterator[PackageManagerLogRecord]:
        for p in self._plugins:
            try:
                yield from getattr(p, f)()
            except Exception:
                self.target.log.exception("Failed to execute package manager plugin: %s.%s", p._name, f)

    @export(record=PackageManagerLogRecord)
    def logs(self) -> Iterator[PackageManagerLogRecord]:
        """Returns logs from all available Unix package managers."""
        yield from self._func("logs")
