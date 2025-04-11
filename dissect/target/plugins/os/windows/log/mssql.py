from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target

MssqlErrorlogRecord = TargetRecordDescriptor(
    "microsoft/sql/errorlog",
    [
        ("datetime", "ts"),
        ("string", "instance"),
        ("string", "process"),
        ("string", "message"),
        ("path", "path"),
    ],
)

RE_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{2}")


class MssqlPlugin(Plugin):
    """Return information related to Microsoft SQL Server.

    Currently returns ERRORLOG messages. These log files contain information such as:
        - Logon failures
        - Enabling/disabling of features, such as xp_cmdshell

    References:
        - https://learn.microsoft.com/en-us/sql/relational-databases/logs/view-offline-log-files
    """

    __namespace__ = "mssql"

    MSSQL_KEY_GLOB = "HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL*.*"
    FILE_GLOB = "ERRORLOG*"

    def __init__(self, target: Target):
        super().__init__(target)
        self.instances = self._find_instances()

    def check_compatible(self) -> None:
        if not self.instances:
            raise UnsupportedPluginError("No Microsoft SQL Server instances have been found")

    @export(record=MssqlErrorlogRecord)
    def errorlog(self) -> Iterator[MssqlErrorlogRecord]:
        """Return all Microsoft SQL Server ERRORLOG messages.

        These log files contain information such as:
         - Logon failures
         - Enabling/disabling of features, such as xp_cmdshell

        Yields MssqlErrorlogRecord instances with fields:

        .. code-block:: text

            ts (datetime): Timestamp of the log line.
            instance (str): SQL Server instance name.
            process (str): Process name.
            message (str): Log message.
            path (Path): Path to the log file.

        References:
            - https://learn.microsoft.com/en-us/sql/relational-databases/logs/view-offline-log-files
        """

        for instance, log_path in self.instances:
            for errorlog in log_path.glob(self.FILE_GLOB):
                # The errorlog includes a BOM, so endianess gets determined automatically
                fh = errorlog.open(mode="rt", encoding="utf-16", errors="surrogateescape")
                buf = ""

                for line in fh:
                    if ts := RE_TIMESTAMP_PATTERN.match(line):
                        yield MssqlErrorlogRecord(
                            ts=datetime.strptime(ts.group(), "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc),
                            instance=instance,
                            # The process name is a fixed-width field and is always 12 characters long.
                            process=buf[23:35].strip(),
                            message=buf[35:].strip(),
                            path=errorlog,
                            _target=self.target,
                        )
                        buf = ""

                    buf += line

    def _find_instances(self) -> set[str, TargetPath]:
        return {
            (subkey.name, self.target.fs.path(subkey.subkey("SQLServerAgent").value("ErrorLogFile").value).parent)
            for subkey in self.target.registry.glob_ext(self.MSSQL_KEY_GLOB)
        }
