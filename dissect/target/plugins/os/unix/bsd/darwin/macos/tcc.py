from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import _build_userdirs
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_sqlite_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

AccessRecord = TargetRecordDescriptor(
    "macos/tcc/access",
    [
        ("string", "table"),
        ("string", "service"),
        ("string", "client"),
        ("varint", "client_type"),
        ("string", "auth_value"),
        ("string", "auth_reason"),
        ("varint", "auth_version"),
        ("bytes", "csreq"),
        ("string", "policy_id"),
        ("string", "indirect_object_identifier"),
        ("string", "indirect_object_identifier_type"),
        ("bytes", "indirect_object_code_identity"),
        ("varint", "flags"),
        ("datetime", "last_modified"),
        ("varint", "pid"),
        ("string", "pid_version"),
        ("string", "boot_uuid"),
        ("datetime", "last_reminded"),
        ("path", "source"),
    ],
)

KeyValueRecord = TargetRecordDescriptor(
    "macos/tcc/key_value",
    [
        ("string", "table"),
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
    ],
)

TCCRecords = (
    AccessRecord,
    KeyValueRecord,
)

VALUE_MAPPINGS = {
    "auth_value": {
        0: "Denied",
        1: "Unknown",
        2: "Allowed",
        3: "Limited",
    },
    "auth_reason": {
        1: "Error",
        2: "User Consent",
        3: "User Set",
        4: "System Set",
        5: "Service Policy",
        6: "MDM Policy",
        7: "Override Policy",
        8: "Missing usage string",
        9: "Prompt Timeout",
        10: "Preflight Unknown",
        11: "Entitled",
        12: "App Type Policy.",
    },
}


class TCCPlugin(Plugin):
    """macOS transparency, consent, control (tcc) framework plugin.

    TCC is a mechanism in macOS to limit and control application access to certain features. This can include
    things such as location services, contacts, photos, microphone, camera, accessibility, full disk access, etc.

    References:
        - https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive
    """

    SYSTEM_PATH = "/Library/Application Support/com.apple.TCC/TCC.db"
    USER_PATH = ("Library/Application Support/com.apple.TCC/TCC.db",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No TCC.db files found")

    def _find_files(self) -> set:
        files = set()
        files.add(self.target.fs.path(self.SYSTEM_PATH))
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

    @export(record=TCCRecords)
    def tcc(
        self,
    ) -> Iterator[TCCRecords]:
        """Return transparency, consent, control (tcc) framework information.

        Yields the following record types:

        .. code-block:: text

            AccessRecord:
                table (string): Source table name (access).
                service (string): What service access is being restricted to.
                client (string):  Bundle Identifier or absolute path to the program that wants to use the service.
                client_type (varint): Whether client is a Bundle Identifier(0) or an absolute path(1)
                auth_value (string): Authorization value.
                auth_reason (string): Indicates how this auth_value was set.
                auth_version (varint): Always 1 as of macOS Tahoe.
                csreq (bytes): Binary code signing requirement blob that the client must
                    satisfy in order for access to be granted.
                policy_id (string): Might be related to MDM(Mobile Device Management) policies, which can
                    be used by organizations to allow TCC access for some applications at a global level.
                indirect_object_identifier (string): For some services this is what the client
                    is asking to interact with. This will be set to UNUSED if not applicable.
                indirect_object_identifier_type (string): Whether indirect_object_identifier is a
                    Bundle Identifier(0) or an absolute path(1)
                indirect_object_code_identity (bytes): Same as csreq, but for the
                    indirect_object_identifier instead of client.
                flags (varint): Always 0 as of macOS Tahoe.
                last_modified (datetime): The last time this entry was modified.
                pid (varint): Process ID.
                pid_version (string): Version of the process.
                boot_uuid (string): System boot session UUID.
                last_reminded (datetime): Last time user was reminded.
                source (path): Path to the TCC.db database file.

            KeyValue:
                table (string): Name of the source table.
                key (string): Key name.
                value (string): Value associated with the key.
                source (path): Path to the TCC.db database file.
        """
        yield from build_sqlite_records(self, self.files, TCCRecords, value_mappings=VALUE_MAPPINGS)

        # TODO: Add policies, active_policy, access_overrides, expired tables
