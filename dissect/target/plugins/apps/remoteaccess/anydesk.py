from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.remoteaccess.remoteaccess import (
    GENERIC_FILE_TRANSFER_RECORD_FIELDS,
    GENERIC_LOG_RECORD_FIELDS,
    RemoteAccessPlugin,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target


class AnydeskPlugin(RemoteAccessPlugin):
    """Anydesk plugin."""

    __namespace__ = "anydesk"

    # Anydesk logs when installed as a service
    SERVICE_GLOBS = (
        # Standard client >= Windows 7
        "sysvol/ProgramData/AnyDesk/*.trace",
        # Custom client >= Windows 7
        "sysvol/ProgramData/AnyDesk/ad_*/*.trace",
        # Windows XP / 2003
        "sysvol/Documents and Settings/Public/AnyDesk/*.trace",
        "sysvol/Documents and Settings/Public/AnyDesk/ad_*/*.trace",
        # Standard/Custom client Linux/MacOS
        "var/log/anydesk*/*.trace",
    )

    # Anydesk Filetransfer logs when installed as a service
    FILETRANSFER_SERVICE_LOGS = (
        # File transfer service log
        "sysvol/ProgramData/AnyDesk/file_transfer_trace.txt",
    )

    # User specific Anydesk filetransfer log
    FILETRANSFER_USER_LOGS = (
        # File transfer log
        "AppData/Roaming/AnyDesk/file_transfer_trace.txt",
    )

    # User specific Anydesk logs
    USER_GLOBS = (
        # Standard client Windows
        "AppData/Roaming/AnyDesk/*.trace",
        # Custom client Windows
        "AppData/Roaming/AnyDesk/ad_*/*.trace",
        # Windows XP / 2003
        "AppData/AnyDesk/*.trace",
        # Standard client Linux/MacOS
        ".anydesk/*.trace",
        # Custom client Linux/MacOS
        ".anydesk_ad_*/*.trace",
    )

    RemoteAccessLogRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "remoteaccess/anydesk/log", GENERIC_LOG_RECORD_FIELDS
    )

    RemoteAccessFileTransferRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "remoteaccess/anydesk/filetransfer", GENERIC_FILE_TRANSFER_RECORD_FIELDS
    )

    def __init__(self, target: Target):
        super().__init__(target)

        self.trace_files: set[tuple[TargetPath, UserDetails | None]] = set()
        self.filetransfer_files: set[tuple[TargetPath, UserDetails | None]] = set()

        # Anydesk trace file service globs
        for trace_glob in self.SERVICE_GLOBS:
            for path in self.target.fs.path().glob(trace_glob):
                self.trace_files.add((path, None))

        # Anydesk filetransfer service globs
        for trace_glob in self.FILETRANSFER_SERVICE_LOGS:
            for path in self.target.fs.path().glob(trace_glob):
                self.filetransfer_files.add((path, None))

        for user_details in self.target.user_details.all_with_home():
            # Anydesk trace file user globs
            for trace_glob in self.USER_GLOBS:
                for path in user_details.home_path.glob(trace_glob):
                    self.trace_files.add((path, user_details.user))

            # Anydesk filetransfer User globs
            for trace_glob in self.FILETRANSFER_USER_LOGS:
                for path in user_details.home_path.glob(trace_glob):
                    self.filetransfer_files.add((path, user_details.user))

    def check_compatible(self) -> None:
        if not self.trace_files and not self.filetransfer_files:
            raise UnsupportedPluginError("No Anydesk files found on target")

    @export(record=RemoteAccessLogRecord)
    def logs(self) -> Iterator[RemoteAccessLogRecord]:
        """Parse AnyDesk trace files.

        AnyDesk is a remote desktop application and can be used by adversaries to get (persistent) access to a machine.
        Log files (.trace files) can be stored on various locations, based on target OS and client type.
        Timestamps in trace files do not carry a time zone designator (TZD) but are in fact UTC.

        References:
            - https://www.inversecos.com/2021/02/forensic-analysis-of-anydesk-logs.html
            - https://support.anydesk.com/knowledge/trace-files#trace-file-locations
        """
        for path, user in self.trace_files:
            for line in path.open("rt", errors="backslashreplace"):
                if not (line := line.strip()) or "* * * * * * * * * * * * * *" in line:
                    continue

                try:
                    level, ts_date, ts_time, message = line.split(" ", 3)

                    timestamp = datetime.strptime(f"{ts_date} {ts_time}", "%Y-%m-%d %H:%M:%S.%f").replace(
                        tzinfo=timezone.utc
                    )
                    message = re.sub(r"\s\s+", " ", f"{level} {message}")

                    yield self.RemoteAccessLogRecord(
                        ts=timestamp,
                        message=message,
                        source=path,
                        _target=self.target,
                        _user=user,
                    )
                except ValueError as e:
                    self.target.log.warning("Could not parse log line in file %s: '%s'", path, line)
                    self.target.log.debug("", exc_info=e)

    @export(record=RemoteAccessFileTransferRecord)
    def filetransfer(self) -> Iterator[RemoteAccessFileTransferRecord]:
        """Parse AnyDesk filetransfer files.

        AnyDesk is a remote desktop application and can be used by adversaries to get (persistent) access to a machine.
        File transfer (``file_transfer_trace.txt``) files show what files are downloaded to a system.
        Timestamps in trace files do not carry a time zone designator (TZD) but are in fact UTC.
        """
        for path, user in self.filetransfer_files:
            for line in path.open("rt", encoding="utf-16-le", errors="backslashreplace"):
                if not (line := line.strip()):
                    continue

                try:
                    # Example log entry:
                    # Clipboard\t\t2025-01-01, 13:37\tstart \tdownload\t'malware.exe' (~0 B out of 4.20 MiB)
                    timestamp = line.split("\t")[2]
                    timestamp = datetime.strptime(timestamp, "%Y-%m-%d, %H:%M").replace(tzinfo=timezone.utc)
                    # Replace log lines tabs with spaces for readability
                    message = line.replace("\t", " ")

                    # Attempt to extract 'filename' from message.
                    filename = match.group(1) if (match := re.search(r"\'([^\']*)\'", message)) else None

                    yield self.RemoteAccessFileTransferRecord(
                        ts=timestamp,
                        message=message,
                        filename=filename,
                        source=path,
                        _target=self.target,
                        _user=user,
                    )
                except ValueError as e:
                    self.target.log.warning("Could not parse log line in file %s: '%s'", path, line)
                    self.target.log.debug("", exc_info=e)
