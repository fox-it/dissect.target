from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from dissect.sql import SQLite3
from dissect.util.ts import wintimestamp
from flow.record.fieldtypes import digest, windows_path

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import (
    TargetRecordDescriptor,
    create_extended_descriptor,
)
from dissect.target.helpers.regutil import (
    RegistryKey,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.sql.sqlite3 import Row

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target


CamRegistryRecord = create_extended_descriptor([RegistryRecordDescriptorExtension, UserRecordDescriptorExtension])(
    "windows/cam/registry",
    [
        ("datetime", "ts"),
        ("string", "device"),
        ("string", "app_name"),
        ("path", "path"),
        ("datetime", "last_started"),
        ("datetime", "last_stopped"),
        ("varint", "duration"),
    ],
)

CamUsageHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/cam/usagehistory",
    [
        ("datetime", "last_used_time_stop"),
        ("datetime", "last_used_time_start"),
        ("varint", "duration"),
        ("string", "package_type"),
        ("string", "capability"),
        ("string", "file_id"),
        ("digest", "file_id_hash"),
        ("string", "access_blocked"),
        ("string", "program_id"),
        ("string", "package_family_name"),
        ("string", "access_guid"),
        ("string", "label"),
        ("string", "app_name"),
        ("path", "binary_full_path"),
        ("string", "service_name"),
    ],
)

CamIdentityRelationshipHistoryRecord = TargetRecordDescriptor(
    "windows/cam/identityrelationshiphistory",
    [
        ("datetime", "last_observed_time"),
        ("string", "package_type"),
        ("string", "file_id"),
        ("digest", "file_id_hash"),
        ("string", "program_id"),
        ("path", "binary_full_path"),
    ],
)

CamGlobalPromptHistoryRecord = TargetRecordDescriptor(
    "windows/cam/globalprompthistory",
    [
        ("datetime", "shown_time"),
        ("string", "package_type"),
        ("string", "capability"),
        ("string", "file_id"),
        ("digest", "file_id_hash"),
        ("string", "program_id"),
    ],
)


class CamPlugin(Plugin):
    """Plugin that iterates various Capability Access Manager registry key locations."""

    __namespace__ = "cam"

    CONSENT_STORES = (
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore",
    )

    CAP_DB_REG_PATH = (
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\CapabilityUsageHistory"
    )

    CONTENT_TABLES = (
        "NonPackagedUsageHistory",
        "PackagedUsageHistory",
        "NonPackagedIdentityRelationship",
        "NonPackagedGlobalPromptHistory",
    )
    CONTEXT_TABLES = (
        "Capabilities",
        "PackageFamilyNames",
        "BinaryFullPaths",
        "Users",
        "FileIDs",
        "ProgramIDs",
        "AccessGUIDs",
        "AppNames",
        "ServiceNames",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.app_regf_keys = self._find_apps()
        self.camdb_path = self._find_db()
        self.camdb: SQLite3 | None = None

    def _find_apps(self) -> list[RegistryKey]:
        return [key for store in self.target.registry.keys(self.CONSENT_STORES) for key in store.subkeys()]

    def check_compatible(self) -> None:
        if not self.app_regf_keys and not self.camdb_path:
            raise UnsupportedPluginError("No Capability Access Manager keys found")

    def yield_apps(self) -> Iterator[RegistryKey]:
        for app in self.app_regf_keys:
            for key in app.subkeys():
                if key.name == "NonPackaged":  # NonPackaged registry key has more apps, so yield those apps
                    yield from key.subkeys()
                else:
                    yield key

    def _find_db(self) -> TargetPath | None:
        try:
            # Retrieve the location of the CapabilityAccessManager.db directory from registry
            DatabaseRoot = self.target.registry.key(self.CAP_DB_REG_PATH).value("DatabaseRoot").value
            camdb_path = self.target.fs.path(DatabaseRoot).joinpath("CapabilityAccessManager.db")

            if camdb_path.exists():
                return camdb_path
        except RegistryKeyNotFoundError:
            # This database and registry key only exists on recent Windows 11 systems.
            self.target.log.warning(
                "cam.history: Cannot find database location registry key, OS probably not supported"
            )

    def _open_db(self) -> SQLite3 | None:
        return SQLite3(self.camdb_path.open("rb")) if self.camdb_path else None

    def _build_context_dict(self) -> defaultdict[str, dict] | None:
        MAPDB = defaultdict(dict)
        for table_name in self.CONTEXT_TABLES:
            for row in self._yield_rows(table_name):
                MAPDB[table_name][row.get("ID")] = row.get("StringValue")
        return MAPDB

    def _convert_ts(self, ts: int) -> None:
        if not ts:
            return None
        return wintimestamp(ts)

    def _convert_file_id(self, file_id: str) -> None:
        return digest((None, file_id[4:], None)) if file_id else None

    def _yield_rows(self, table_name: str) -> Iterator[Row]:
        if not (table := self.camdb.table(table_name)):
            return
        yield from table

    @export(record=[CamUsageHistoryRecord, CamIdentityRelationshipHistoryRecord, CamGlobalPromptHistoryRecord])
    def history(
        self,
    ) -> Iterator[CamUsageHistoryRecord | CamIdentityRelationshipHistoryRecord | CamGlobalPromptHistoryRecord]:
        """Iterate Capability Access Manager History entries.
        The Capability Access Manager keeps track of processes that access I/O devices, like the webcam or microphone.
        Applications are divided into packaged and non-packaged applications meaning Microsoft or
        non-Microsoft applications. Additional historical entries are since Windows 11 available in a SQL database.

        Records are created from the following tables:
        - NonPackagedUsageHistory
        - PackagedUsageHistory
        - NonPackagedIdentityRelationship
        - NonPackagedGlobalPromptHistory

        References:
            - https://medium.com/@cyber.sundae.dfir/capability-access-manager-forensics-in-windows-11-f586ef8aac79

        Yields ``CamUsageHistoryRecord``, ``CamIdentityRelationshipHistoryRecord`` or ``CamGlobalPromptHistoryRecord``:

        Record CamUsageHistoryRecord:

        .. code-block:: text

            last_used_time_stop (datetime): When the application last stopped using the capability.
            last_used_time_start (datetime): When the application last started using the capability.
            duration (varint): How long the application used the capability.
            package_type (string): The application type of the record, originates from the table name.
            capability (string): The capability being used; microphone, camera, location etc.
            file_id (string): The sha1 hash of the application making use of the capability.
            file_id_hash (digest): Digest version of the file_id field.
            access_blocked (string): If capability usage was allowed, 0 = Not blocked and 1 = blocked.
            program_id (string): Program ID of application, unclear what this value means.
            package_family_name (string): Package name of application using capability.
            access_guid (string): Unclear what the value of this is.
            label (string): Unclear what the value of this is, no joinable table with this ID.
            app_name (string): Name of the application using capability.
            binary_full_path (path): Path of the application using capability.
            service_name (string): Name of the service using capability.

        Record CamIdentityRelationshipHistoryRecord:

        .. code-block:: text

            last_observed_time (datetime): Last time capability was observed.
            package_type (string): The application type of the record, originates from the table name.
            file_id (string): The sha1 hash of the application making use of the capability.
            file_id_hash (digest): Digest version of the file_id field.
            program_id (string): Program ID of application, unclear what this value means.
            binary_full_path (path): Path of the application using capability.

        Record CamGlobalPromptHistoryRecord

        .. code-block:: text

            shown_time (datetime): Last time capability was observed.
            package_type (string): The application type of the record, originates from the table name.
            capability (string): The capability being used; microphone, camera, location etc.
            file_id (string): The sha1 hash of the application making use of the capability.
            file_id_hash (digest): Digest version of the file_id field.
            program_id (string): Program ID of application, unclear what this value means.
        """

        self.camdb = self._open_db()

        # Silently exit the function if no database object could be created.
        # This means the function is not compatible with the target.
        if not self.camdb:
            return None

        # Create mapping dict for sql 'join' actions.
        MAPDB = self._build_context_dict()

        # Process NonPackagedUsageHistory and PackagedUsageHistory tables
        for table_name in ["NonPackagedUsageHistory", "PackagedUsageHistory"]:
            for row in self._yield_rows(table_name):
                # Resolve user from UserSID
                if user := self.target.user_details.find(MAPDB["Users"].get(row["UserSid"], "")):
                    user = user.user

                # Calculate duration field
                duration = 0
                last_used_time_stop = self._convert_ts(row.get("LastUsedTimeStop"))
                last_used_time_start = self._convert_ts(row.get("LastUsedTimeStart"))

                if all([last_used_time_stop, last_used_time_start]):
                    duration = last_used_time_stop.timestamp() - last_used_time_start.timestamp()

                yield CamUsageHistoryRecord(
                    last_used_time_stop=last_used_time_stop,
                    last_used_time_start=last_used_time_start,
                    duration=duration,
                    package_type=table_name,
                    capability=MAPDB["Capabilities"].get(row["Capability"]),
                    file_id=MAPDB["FileIDs"].get(row["FileID"]),
                    file_id_hash=self._convert_file_id(MAPDB["FileIDs"].get(row["FileID"])),
                    access_blocked=row["AccessBlocked"],
                    access_guid=MAPDB["AccessGUIDs"].get(row["AccessGUID"]),
                    label=row["Label"],
                    app_name=MAPDB["AppNames"].get(row["AppName"]),
                    program_id=MAPDB["ProgramIDs"].get(row["ProgramID"]),
                    binary_full_path=MAPDB["BinaryFullPaths"].get(row["BinaryFullPath"]),
                    package_family_name=MAPDB["PackageFamilyNames"].get(row["PackageFamilyName"]),
                    service_name=MAPDB["ServiceNames"].get(row["ServiceName"]),
                    _target=self.target,
                    _user=user,
                )

        # Process table NonPackagedIdentityRelationship
        for row in self._yield_rows("NonPackagedIdentityRelationship"):
            yield CamIdentityRelationshipHistoryRecord(
                last_observed_time=self._convert_ts(row.get("LastObservedTime")),
                package_type=table_name,
                file_id=MAPDB["FileIDs"].get(row["FileID"]),
                file_id_hash=self._convert_file_id(MAPDB["FileIDs"].get(row["FileID"])),
                program_id=MAPDB["ProgramIDs"].get(row["ProgramID"]),
                binary_full_path=MAPDB["BinaryFullPaths"].get(row["BinaryFullPath"]),
                _target=self.target,
            )

        # Process table NonPackagedGlobalPromptHistory
        for row in self._yield_rows("NonPackagedGlobalPromptHistory"):
            yield CamGlobalPromptHistoryRecord(
                shown_time=self._convert_ts(row.get("ShownTime")),
                package_type=table_name,
                capability=MAPDB["Capabilities"].get(row["Capability"]),
                file_id=MAPDB["FileIDs"].get(row["FileID"]),
                file_id_hash=self._convert_file_id(MAPDB["FileIDs"].get(row["FileID"])),
                program_id=MAPDB["ProgramIDs"].get(row["ProgramID"]),
                _target=self.target,
            )

    @export(record=CamRegistryRecord)
    def registry(self) -> Iterator[CamRegistryRecord]:
        """Iterate Capability Access Manager key locations.

        The Capability Access Manager keeps track of processes that access I/O devices, like the webcam or microphone.
        Applications are divided into packaged and non-packaged applications meaning Microsoft or
        non-Microsoft applications.

        References:
            - https://docs.velociraptor.app/exchange/artifacts/pages/windows.registry.capabilityaccessmanager/
            - https://svch0st.medium.com/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072

        Yields ``CamRegistryRecord`` with the following fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The modification timestamp of the registry key.
            device (string): Name of the device privacy permission where asked for.
            app_name (string): The name of the application.
            path (path): The possible path to the application.
            last_started (datetime): When the application last started using the device.
            last_stopped (datetime): When the application last stopped using the device.
            duration (varint): How long the application used the device (seconds).
        """

        for key in self.yield_apps():
            last_started = None
            last_stopped = None
            duration = None

            try:
                last_started = wintimestamp(key.value("LastUsedTimeStart").value)
            except RegistryValueNotFoundError:
                self.target.log.warning("No LastUsedTimeStart for application: %s", key.name)

            try:
                last_stopped = wintimestamp(key.value("LastUsedTimeStop").value)
            except RegistryValueNotFoundError:
                self.target.log.warning("No LastUsedTimeStop for application: %s", key.name)

            if last_started and last_stopped:
                duration = (last_stopped - last_started).seconds

            # The "device" is derived from the subkey (webcam in this case) of ConsentStore example:
            # HKLM\\...\\CapabilityAccessManager\\ConsentStore\\webcam\\C:#Program Files#Mozilla Firefox#firefox.exe
            device = key.path.split("\\")[-2]

            # The application/or path of the application using the device is the key.name itself:
            # C:#Program Files#Mozilla Firefox#firefox.exe
            path = windows_path(key.name.replace("#", "\\")) if "#" in key.name else None

            yield CamRegistryRecord(
                ts=key.ts,
                device=device,
                app_name=key.name,
                path=path,
                last_started=last_started,
                last_stopped=last_stopped,
                duration=duration,
                _target=self.target,
                _key=key,
                _user=self.target.registry.get_user(key),
            )
