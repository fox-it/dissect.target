from __future__ import annotations
import re
from datetime import datetime
from typing import TYPE_CHECKING, Iterator
import logging

from dissect.target.plugin import Plugin, export
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.exceptions import UnsupportedPluginError

if TYPE_CHECKING:
    from dissect.target import Target

log = logging.getLogger(__name__)

AgentExecutorLogRecord = TargetRecordDescriptor(
    "agentexecutor/log",
    [
        ("datetime", "timestamp"),
        ("string", "component"),
        ("string", "thread"),
        ("string", "type"),
        ("string", "context"),
        ("string", "message"),
        ("string", "file_origin"),
    ],
)

LOG_PATTERN = re.compile(
    r'<!\[LOG\[(?P<message>.*?)\]LOG\]!>'
    r'<time="(?P<hms>\d{2}:\d{2}:\d{2})(?:\.(?P<fractional_seconds>\d{1,7}))?"\s+'
    r'date="(?P<date>[\d-]+)"\s+'
    r'component="(?P<component>[^"]+)"\s+'
    r'context="(?P<context>[^"]*)"\s+'
    r'type="(?P<type>\d+)"\s+'
    r'thread="(?P<thread>\d+)"'
    r'(?:\s+file="(?P<file_origin>[^"]*)")?',
    re.DOTALL | re.IGNORECASE,
)

class AgentExecutorLogPlugin(Plugin):
    """Parse Microsoft Intune AgentExecutor logs.

    The AgentExecutor log file captures script execution and system management
    activity from the Microsoft Intune Management Extension agent.
    This plugin parses structured entries and converts them into records suitable
    for timeline and forensic analysis.
    """

    DEFAULT_LOG_PATH = "sysvol/ProgramData/Microsoft/IntuneManagementExtension/Logs/AgentExecutor.log"
    

    def check_compatible(self) -> None:
        """Verify that the AgentExecutor log file exists within the target.

        Raises:
            UnsupportedPluginError: If the expected log file does not exist.
        """
        log_path = self.target.fs.path(self.DEFAULT_LOG_PATH)
        if not log_path.exists():
            raise UnsupportedPluginError(
                f"AgentExecutor.log not found at {self.DEFAULT_LOG_PATH}"
            )

    @export(record=AgentExecutorLogRecord)
    def agentexecutor(self) -> Iterator[AgentExecutorLogRecord]:
        """Parse the AgentExecutor.log and yield structured records.

        Extracts timestamp, message, context, thread, and type information from
        the AgentExecutor log and yields normalized structured records.

        Yields:
            AgentExecutorLogRecord: A structured representation of each log entry.
        """
        log_path = self.target.fs.path(self.DEFAULT_LOG_PATH)

        try:
            with log_path.open("r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            log.exception(f"Failed to open log file {log_path}: {e}")
            return

        match_count = 0

        for match in LOG_PATTERN.finditer(content):
            match_count += 1

            msg = match.group("message").replace("\r", "").strip()
            date_str = match.group("date")
            hms_str = match.group("hms")
            fractional_seconds_str = match.group("fractional_seconds")

            micro_str = (fractional_seconds_str or "000000")[:6].ljust(6, "0")
            time_str = f"{hms_str}.{micro_str}"

            timestamp = None
            for fmt in ("%m-%d-%Y %H:%M:%S.%f", "%d-%m-%Y %H:%M:%S.%f"):
                try:
                    timestamp = datetime.strptime(f"{date_str} {time_str}", fmt)
                    break
                except ValueError:
                    continue

            if not timestamp:
                log.debug(f"Could not parse datetime from {date_str} {time_str}")
                continue

            iso_timestamp = timestamp.isoformat(timespec="microseconds")
            log_type = match.group("type")

            yield AgentExecutorLogRecord(
                timestamp=iso_timestamp,
                component=match.group("component"),
                thread=match.group("thread"),
                type=log_type,
                context=match.group("context"),
                message=msg,
                file_origin=match.group("file_origin") or "AgentExecutor.log",
                _target=self.target,
            )

        if match_count == 0:
            log.warning(f"No log entries matched the regex in {log_path}")
