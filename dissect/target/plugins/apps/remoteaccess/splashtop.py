from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import export
from dissect.target.plugins.apps.remoteaccess.remoteaccess import (
    GENERIC_FILE_TRANSFER_RECORD_FIELDS,
    GENERIC_LOG_RECORD_FIELDS,
    RemoteAccessPlugin,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target


RE_TS = re.compile(r"(\w{3}\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})")


class SplashtopPlugin(RemoteAccessPlugin):
    """Splashtop plugin."""

    __namespace__ = "splashtop"

    RemoteAccessLogRecord = TargetRecordDescriptor(
        "remoteaccess/splashtop/log",
        GENERIC_LOG_RECORD_FIELDS,
    )

    RemoteAccessFileTransferRecord = TargetRecordDescriptor(
        "remoteaccess/splashtop/filetransfer",
        GENERIC_FILE_TRANSFER_RECORD_FIELDS,
    )

    LOG_PATHS = (
        # General agent log including connections and filetransfers
        "sysvol/Program Files (x86)/Splashtop/Splashtop Remote/Server/log/SPLog.txt",
        # File transfer log which is currently acquired but not parsed
        # All content is also included in the SPLog so no need to parse
        # acquired the file just in case something is missing in the SPLog
        # "sysvol/ProgramData/Splashtop/Temp/log/FTCLog.txt",
    )

    def __init__(self, target: Target):
        super().__init__(target)

        self.log_files: set[TargetPath] = set()

        for log_path in self.LOG_PATHS:
            if (log_file := self.target.fs.path(log_path)).exists():
                self.log_files.add(log_file)

    def check_compatible(self) -> None:
        if not self.log_files:
            raise UnsupportedPluginError("No Splashtop log files found on target")

    @export(record=RemoteAccessLogRecord)
    def logs(self) -> Iterator[RemoteAccessLogRecord]:
        """Parse Splashtop log files.

        Splashtop is a remote desktop application that can be used to get (persistent) access to a machine.
        It might be used in combination with Atera Management Agent.

        References:
            - https://www.synacktiv.com/en/publications/legitimate-rats-a-comprehensive-forensic-analysis-of-the-usual-suspects#atera-and-splashtop
        """
        target_tz = self.target.datetime.tzinfo

        for log_file in self.log_files:
            try:
                for ts, line in year_rollover_helper(log_file, RE_TS, "%b%d %H:%M:%S.%f", target_tz):
                    try:
                        # The line is of format "<#>%b%d %H:%M:%S.%f ..." check if the start matches an expected line
                        if (line[0], line[2]) != ("<", ">"):
                            self.target.log.error("LINE %s", line)
                            raise ValueError("Line does not match expected format")  # noqa: TRY301

                        # The prefix contains two spaces splitting off the timestamp, grab only the message part
                        message = line.split(" ", maxsplit=2)[-1]

                        yield self.RemoteAccessLogRecord(
                            ts=ts,
                            message=message,
                            source=log_file,
                            _target=self.target,
                        )
                    except ValueError as e:  # noqa: PERF203
                        self.target.log.warning("Could not parse log line in file %s: %r", log_file, line)
                        self.target.log.debug("", exc_info=e)
            except Exception as e:  # noqa: PERF203
                self.target.log.warning("Could not parse log file %s", log_file)
                self.target.log.debug("", exc_info=e)

    @export(record=RemoteAccessFileTransferRecord)
    def filetransfer(self) -> Iterator[RemoteAccessFileTransferRecord]:
        """Parse Splashtop filetransfers.

        Splashtop is a remote desktop application and can be used by adversaries to get (persistent) access to a
        machine. File transfers as logged in the generic logfile (``SPLog.txt``) show what files are downloaded
        to a system.
        """
        methods = ("OnUploadRequest", "OnUploadFileCPRequest", "OnDownloadRequest")
        for log_record in self.logs():
            try:
                # Example log entry:
                # SM_03280[FTCnnel] OnUploadFileCPRequest 1, 1 =>{"fileID":"353841253","fileName":"NOTE.txt","fileSize":"34","remotesessionFTC":1,"request":"uploadFile"}  # noqa: E501

                if any(method in log_record.message for method in methods):
                    json_data = json.loads(log_record.message.split("=>")[1])

                    yield self.RemoteAccessFileTransferRecord(
                        ts=log_record.ts,
                        message=log_record.message,
                        source=log_record.source,
                        filename=json_data["fileName"],
                        _target=self.target,
                    )
            except Exception as e:  # noqa: PERF203
                self.target.log.warning(
                    "Could not parse file transfer from message in file %s: %r", log_record.source, log_record.message
                )
                self.target.log.debug("", exc_info=e)
