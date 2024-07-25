import re
from datetime import datetime, timezone
from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.remoteaccess.remoteaccess import (
    GENERIC_LOG_RECORD_FIELDS,
    RemoteAccessPlugin,
)
from dissect.target.plugins.general.users import UserDetails


class AnydeskPlugin(RemoteAccessPlugin):
    """Anydesk plugin."""

    __namespace__ = "anydesk"

    # Anydesk logs when installed as a service
    SERVICE_GLOBS = [
        # Standard client >= Windows 7
        "sysvol/ProgramData/AnyDesk/*.trace",
        # Custom client >= Windows 7
        "sysvol/ProgramData/AnyDesk/ad_*/*.trace",
        # Windows XP / 2003
        "sysvol/Documents and Settings/Public/AnyDesk/*.trace",
        "sysvol/Documents and Settings/Public/AnyDesk/ad_*/*.trace",
        # Standard/Custom client Linux/MacOS
        "var/log/anydesk*/*.trace",
    ]

    # User specific Anydesk logs
    USER_GLOBS = [
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
    ]

    RemoteAccessLogRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "remoteaccess/anydesk/log", GENERIC_LOG_RECORD_FIELDS
    )

    def __init__(self, target):
        super().__init__(target)

        self.trace_files: set[tuple[TargetPath, UserDetails]] = set()

        # Service globs
        user = None
        for trace_glob in self.SERVICE_GLOBS:
            for trace_file in self.target.fs.path().glob(trace_glob):
                self.trace_files.add((trace_file, user))

        # User globs
        for user_details in self.target.user_details.all_with_home():
            for trace_glob in self.USER_GLOBS:
                for trace_file in user_details.home_path.glob(trace_glob):
                    self.trace_files.add((trace_file, user_details.user))

    def check_compatible(self) -> None:
        if not self.trace_files:
            raise UnsupportedPluginError("No Anydesk trace files found on target")

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
        for trace_file, user in self.trace_files:
            for line in trace_file.open("rt", errors="backslashreplace"):
                line = line.strip()

                if not line or "* * * * * * * * * * * * * *" in line:
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
                        source=trace_file,
                        _target=self.target,
                        _user=user,
                    )

                except ValueError as e:
                    self.target.log.warning("Could not parse log line in file %s: '%s'", trace_file, line)
                    self.target.log.debug("", exc_info=e)
