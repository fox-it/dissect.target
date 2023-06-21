import json
from typing import Iterator

from dissect.sql import sqlite3
from dissect.util.ts import wintimestamp
from flow.record.fieldtypes import path

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

HitmanAlertRecord = TargetRecordDescriptor(
    "application/av/sophos/hitman/log",
    [
        ("datetime", "ts"),
        ("string", "alert"),
        ("string", "description"),
        ("string", "details"),
    ],
)

SophosLogRecord = TargetRecordDescriptor(
    "application/av/sophos/home/log",
    [
        ("datetime", "ts"),
        ("string", "description"),
        ("path", "path"),
    ],
)


class SophosPlugin(Plugin):
    __namespace__ = "sophos"

    LOG_SOPHOS_HOME = "sysvol/ProgramData/Sophos/Clean/Logs/Clean.log"
    LOG_SOPHOS_HITMAN = "sysvol/ProgramData/HitmanPro.Alert/excalibur.db"
    MARKER_INFECTION = '{"command":"clean-threat'

    LOGS = [LOG_SOPHOS_HOME, LOG_SOPHOS_HITMAN]

    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self.codepage = self.target.codepage or "ascii"

    def check_compatible(self) -> bool:
        is_compatible = False
        for marker in self.LOGS:
            if self.target.fs.path(marker).exists():
                is_compatible = True
                break
        if not is_compatible:
            raise UnsupportedPluginError("No Sophos/Hitman logs found")

    @export(record=HitmanAlertRecord)
    def hitmanlogs(self) -> Iterator[HitmanAlertRecord]:
        """Return alert log records from Sophos Hitman Pro/Alert.

        Yields HitmanAlertRecord with the following fields:
            ts (datetime): Timestamp.
            alert (string): Type of Alert.
            description (string): Short description of the alert.
            details (string): Detailed description of the alert.

        Note that because Hitman also catches suspicious behaviour of
        systems, the details field might contain a lot of text, it might
        contain stracktraces etc.
        """
        try:
            fh = self.target.fs.path(self.LOG_SOPHOS_HITMAN).open("rb")
            db = sqlite3.SQLite3(fh)
            alerts = list(filter(lambda t: t.name == "Alerts", db.tables()))[0]
            for alert in alerts.rows():
                yield HitmanAlertRecord(
                    ts=wintimestamp(alert.Timestamp),  # already utc
                    alert=alert.AlertType,
                    description=alert.Description,
                    details=alert.Details,
                    _target=self.target,
                )
        except Exception as error:
            self.target.log.error(f"Error occurred during reading alerts: {error}.")

    @export(record=SophosLogRecord)
    def sophoshomelogs(self) -> Iterator[SophosLogRecord]:
        """Return log history records from Sophos Home.

        Yields SophosLogRecord with the following fields:
            ts (datetime): Timestamp.
            description (string): Short description of the alert.
            path (path): Path to the infected file (if available).

        """
        log = self.target.fs.path(self.LOG_SOPHOS_HOME).open("rt", 0, "utf-16le")
        while line := log.readline():
            if line.find(self.MARKER_INFECTION) > -1:
                try:
                    ts, json_data = line.split(" ", maxsplit=2)
                    details = json.loads(json_data)

                    path_to_infected_file = None
                    if targets := details.get("targets", None):
                        path_to_infected_file = targets[0].get("file_path", None)

                    yield SophosLogRecord(
                        ts=ts,
                        description=details.get("threat_name", details),
                        path=path.from_windows(path_to_infected_file),
                        _target=self.target,
                    )
                except Exception as error:
                    self.target.log.warning(f"Error: {error} on log line: {line}.")
