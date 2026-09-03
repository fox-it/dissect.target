from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

TimeMachineRecord = TargetRecordDescriptor(
    "macos/time_machine",
    [
        ("string", "last_destination_id"),
        ("varint", "auto_backup_interval"),
        ("string[]", "host_uuids"),
        ("boolean", "requires_ac_power"),
        ("datetime", "suspend_helper_activity_timestamp"),
        ("bytes", "backup_alias"),
        ("varint", "preferences_version"),
        ("varint", "auto_backup"),
        ("datetime", "last_activity_backup"),
        ("path", "source"),
    ],
)

DestinationsRecord = TargetRecordDescriptor(
    "macos/time_machine/destination",
    [
        ("string[]", "destination_uuids"),
        ("string", "last_known_volume_name"),
        ("varint", "result"),
        ("string", "filesystem_type_name"),
        ("string", "last_known_encryption_state"),
        ("datetime", "stable_local_snapshot_date"),
        ("varint", "inheritance_decision"),
        ("string", "destination_id"),
        ("varint", "bytes_used"),
        ("varint", "destination_version"),
        ("varint", "health_check_decision"),
        ("varint", "smb_conversion_state"),
        ("datetime[]", "attempt_dates"),
        ("varint", "bytes_available"),
        ("path", "source"),
    ],
)


class TimeMachinePlugin(Plugin):
    """macOS Time Machine plugin.

    Parses Time Machine, macOS's backup system, preferences.
    """

    PATH = "/Library/Preferences/com.apple.TimeMachine.plist"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = self.target.fs.path(self.PATH) if self.target.fs.path(self.PATH).exists() else None

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No com.apple.TimeMachine.plist file found")

    @export(record=(TimeMachineRecord, DestinationsRecord))
    def time_machine(self) -> Iterator[(TimeMachineRecord, DestinationsRecord)]:
        """Return macOS Time Machine preferences.

        Yields the following record types extracted from the
        com.apple.TimeMachine.plist file:

        .. code-block:: text

            TimeMachineRecord:
                last_destination_id (string): Identifier of the last used backup destination.
                auto_backup_interval (varint): Interval between automatic backups.
                host_uuids (string[]): List of host UUIDs associated with the backup configuration.
                requires_ac_power (boolean): Indicates whether backups require AC power.
                suspend_helper_activity_timestamp (datetime): Timestamp when helper activity was suspended.
                backup_alias (bytes): Binary backup alias.
                preferences_version (varint): Version of the Time Machine preferences.
                auto_backup (varint): Flag indicating whether automatic backups are enabled.
                last_activity_backup (datetime): Timestamp of the last backup activity.
                source (path): Path to the com.apple.TimeMachine.plist file.

            DestinationsRecord:
                destination_uuids (string[]): List of destination UUIDs.
                last_known_volume_name (string): Name of the backup volume.
                result (varint): Result code of the last backup operation.
                filesystem_type_name (string): Filesystem type of the destination.
                last_known_encryption_state (string): Encryption state of the backup destination.
                stable_local_snapshot_date (datetime): Timestamp of the last stable local snapshot.
                inheritance_decision (varint): Indicates inheritance decision state.
                destination_id (string): Identifier for the destination.
                bytes_used (varint): Amount of bytes used on the destination.
                destination_version (varint): Destination version.
                health_check_decision (varint): Health check decision.
                smb_conversion_state (varint): SMB conversion state indicator.
                attempt_dates (datetime[]): List of backup attempt timestamps.
                bytes_available (varint): Available bytes on the destination.
                source (path): Path to the com.apple.TimeMachine.plist file.
        """
        plist = plistlib.load(self.file.open())

        yield TimeMachineRecord(
            last_destination_id=plist.get("PreferencesLastDestinationIDVersion"),
            auto_backup_interval=plist.get("AutoBackupInterval"),
            host_uuids=plist.get("HostUUIDs"),
            requires_ac_power=plist.get("RequiresACPower"),
            suspend_helper_activity_timestamp=plist.get("SuspendHelperActivityTimeStamp"),
            backup_alias=plist.get("BackupAlias"),
            preferences_version=plist.get("PreferencesVersion"),
            auto_backup=plist.get("AutoBackup"),
            last_activity_backup=plist.get("LastBackupActivity"),
            source=self.file,
            _target=self.target,
        )

        destinations = plist.get("Destinations")
        if destinations:
            for destination in destinations:
                yield DestinationsRecord(
                    destination_uuids=destination.get("DestinationUUIDs"),
                    last_known_volume_name=destination.get("LastKnownVolumeName"),
                    result=destination.get("RESULT"),
                    filesystem_type_name=destination.get("FilesystemTypeName"),
                    last_known_encryption_state=destination.get("LastKnownEncryptionState"),
                    stable_local_snapshot_date=destination.get("StableLocalSnapshotDate"),
                    inheritance_decision=destination.get("InheritanceDecision"),
                    destination_id=destination.get("DestinationID"),
                    bytes_used=destination.get("BytesUsed"),
                    destination_version=destination.get("DestinationVersion"),
                    health_check_decision=destination.get("HealthCheckDecision"),
                    smb_conversion_state=destination.get("SMBConversionState"),
                    attempt_dates=destination.get("AttemptDates"),
                    bytes_available=destination.get("BytesAvailable"),
                    source=self.file,
                    _target=self.target,
                )
