from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Final

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import NamespacePlugin

if TYPE_CHECKING:
    from typing_extensions import Self

PackageManagerLogRecord = TargetRecordDescriptor(
    "unix/packagemanager/log",
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
    """Valid operation types."""

    Install = "install"
    Update = "update"
    Downgrade = "downgrade"
    Remove = "remove"
    Other = "other"

    __MAPPING__: Final[dict[str, list[str]]] = {
        Install: ["install", "installed", "reinstall"],
        Update: ["update", "updated", "upgrade"],
        Downgrade: ["downgrade"],
        Remove: ["remove", "removed", "erased", "purge"],
        Other: ["command"],
    }

    @classmethod
    def infer(cls, keyword: str) -> Self:
        keyword = keyword.strip().lower()
        for key, values in cls.__MAPPING__.items():
            if keyword in values:
                return OperationTypes(key)
        return OperationTypes.Other


class PackageManagerPlugin(NamespacePlugin):
    __namespace__ = "packagemanager"
