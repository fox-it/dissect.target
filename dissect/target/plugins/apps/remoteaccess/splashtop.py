from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
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
    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target


RE_TS = re.compile(r"(\w{3}\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})")
RE_LOG_LINE = re.compile(r"<[0-9]>\w{3}\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3}\s(.*)")


class SplashtopPlugin(RemoteAccessPlugin):
    """Splashtop plugin."""

    __namespace__ = "splashtop"

    RemoteAccessLogRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "remoteaccess/splashtop/log", GENERIC_LOG_RECORD_FIELDS
    )

    RemoteAccessFileTransferRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "remoteaccess/splashtop/filetransfer", GENERIC_FILE_TRANSFER_RECORD_FIELDS
    )

    LOG_PATHS = ("sysvol/Program Files (x86)/Splashtop/Splashtop Remote/Server/log/SPLog.txt",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.log_files: set[tuple[TargetPath, UserDetails | None]] = set()

        for log_path in self.LOG_PATHS:
            log_file = self.target.fs.path(log_path)
            if log_file:
                self.log_files.add((log_file, None))

    def check_compatible(self) -> None:
        if not self.log_files:
            raise UnsupportedPluginError("No Splashtop log files found on target")

    @export(record=RemoteAccessLogRecord)
    def logs(self) -> Iterator[RemoteAccessLogRecord]:
        """Parse Splashtop log files.

        Splashtop is a remote desktop application that can be used to get (persistent) access to a machine.
        It might be used in combination with Atera Management Agent.

        Refrences:
            - https://www.synacktiv.com/en/publications/legitimate-rats-a-comprehensive-forensic-analysis-of-the-usual-suspects#atera-and-splashtop
        """
        target_tz = self.target.datetime.tzinfo

        for log_file, user in self.log_files:
            for ts, line in year_rollover_helper(log_file, RE_TS, "%b%d %H:%M:%S.%f", target_tz):
                if line := line.strip():
                    try:
                        if not (match := RE_LOG_LINE.match(line)):
                            self.target.log.error("LINE %s", line)
                            raise ValueError("Line does not match expected format")  # noqa: TRY301

                        message = match.group(1)

                        yield self.RemoteAccessLogRecord(
                            ts=ts,
                            message=message,
                            source=log_file,
                            _target=self.target,
                            _user=user,
                        )
                    except ValueError as e:
                        self.target.log.warning("Could not parse log line in file %s: '%s'", log_file, line)
                        self.target.log.debug("", exc_info=e)

    @export(record=RemoteAccessFileTransferRecord)
    def filetransfer(self) -> Iterator[RemoteAccessFileTransferRecord]:
        """Parse Splashtop filetransfers.

        Splashtop is a remote desktop application and can be used by adversaries to get (persistent) access to a machine.
        File transfers as logged in the generic logfile (``SPLog.txt``) show what files are downloaded to a system.
        """
        for log_record in self.logs():
            try:
                # Example log entry:
                # SM_03280[FTCnnel] OnUploadFileCPRequest 1, 1 =>{"fileID":"353841253","fileName":"NOTE.txt","fileSize":"34","remotesessionFTC":1,"request":"uploadFile"}
                if "OnUploadFileCPRequest" in log_record.message:
                    upload_json = json.loads(log_record.message.split("=>")[1])

                    kwargs = log_record._asdict()
                    kwargs["filename"] = upload_json["fileName"]
                    yield self.RemoteAccessFileTransferRecord(**kwargs)
            except ValueError as e:
                self.target.log.warning(
                    "Could not parse file transfer from message in file %s: '%s'", log_record.source, log_record.message
                )
                self.target.log.debug("", exc_info=e)
