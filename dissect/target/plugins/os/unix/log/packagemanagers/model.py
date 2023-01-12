import enum

from dissect.target.helpers.record import TargetRecordDescriptor


class OperationTypes(enum.Enum):
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
    def infer(cls, keyword: str):
        keyword = keyword.strip().lower()
        for key, values in cls.__MAPPING__.items():
            if keyword in values:
                return OperationTypes(key)
        return OperationTypes.Other


PackageManagerLogRecord = TargetRecordDescriptor(
    "linux/log/packagemanager",
    [
        ("string", "package_manager"),
        ("datetime", "ts"),
        ("string", "operation"),
        ("string", "package_name"),
        ("string", "command"),
        ("string", "user"),
    ],
)
