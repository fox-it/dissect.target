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

PackageManagerPackageRecord = TargetRecordDescriptor(
    "unix/packagemanager/package",
    [
        ("datetime", "ts"),
        ("string", "package_manager"),
        ("string", "package_name"),
        ("string", "package_name_full"),
        ("string", "package_version"),
        ("string", "package_release"),
        ("string", "package_arch"),
        ("string", "package_vendor"),
        ("string", "package_summary"),
        ("filesize", "package_size"),
        ("string", "package_archive"),
        ("digest", "digest"),  # digest of the archive
        ("path[]", "package_files"),
        ("digest[]", "package_files_digests"),
        ("path", "source"),
    ],
)

PackageManagerPackageFileRecord = TargetRecordDescriptor(
    "unix/packagemanager/package/file",
    [
        ("datetime", "ts"),
        ("string", "package_manager"),
        ("string", "package_name"),
        ("string", "package_name_full"),
        ("path", "path"),
        ("boolean", "exists"),
        ("filesize", "stored_size"),
        ("filesize", "actual_size"),
        ("digest", "stored_digest"),
        ("digest", "actual_digest"),
        ("boolean", "digest_match"),
        ("path", "source"),
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
