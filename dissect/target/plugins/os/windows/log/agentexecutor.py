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

# ------------------------------------------------------------------------------
# Logger setup
# ------------------------------------------------------------------------------
log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------
# Record Descriptor
# ------------------------------------------------------------------------------
# Defines the structure of parsed AgentExecutor log entries.
AgentExecutorLogRecord = TargetRecordDescriptor(
    "agentexecutor/log",
    [
        ("datetime", "timestamp"),   # Timestamp of the log entry
        ("string", "component"),     # Log component name (e.g., AgentExecutor)
        ("string", "thread"),        # Thread ID or identifier
        ("string", "type"),          # Log type (e.g., INFO, ERROR)
        ("string", "context"),       # Log context field (may contain scope or process info)
        ("string", "message"),       # The actual log message
        ("string", "file_origin"),   # Source log file name (useful if multiple)
    ],
)

# ------------------------------------------------------------------------------
# Regular Expression Pattern
# ------------------------------------------------------------------------------
# Matches Microsoft Intune AgentExecutor log lines, which typically look like:
# <![LOG[Message text]LOG]!><time="11:36:54.1412934" date="12-2-2024"
# component="AgentExecutor" context="" type="1" thread="1" file="">
#
# The regex extracts all key fields including context, supporting multiline messages.
LOG_PATTERN = re.compile(
    r'<!\[LOG\[(?P<message>.*?)\]LOG\]!>'                                           # Log message
    r'<time="(?P<hms>\d{2}:\d{2}:\d{2})(?:\.(?P<fractional_seconds>\d{1,7}))?"\s+'  # Time (with optional microseconds)
    r'date="(?P<date>[\d-]+)"\s+'                                                   # Date (day-month-year)
    r'component="(?P<component>[^"]+)"\s+'                                          # Component name
    r'context="(?P<context>[^"]*)"\s+'                                              # Context field (can be empty)
    r'type="(?P<type>\d+)"\s+'                                                      # Log type (1=Info, 2=Error, etc.)
    r'thread="(?P<thread>\d+)"'                                                     # Thread ID
    r'(?:\s+file="(?P<file_origin>[^"]*)")?',                                       # Optional file attribute
    re.DOTALL | re.IGNORECASE,
)

# ------------------------------------------------------------------------------
# Plugin Definition
# ------------------------------------------------------------------------------

class AgentExecutorLogPlugin(Plugin):
    """Parse Microsoft Intune AgentExecutor logs.

    The AgentExecutor log file captures script execution and system management
    activity from the Microsoft Intune Management Extension agent.
    This plugin parses structured entries and converts them into records suitable
    for timeline and forensic analysis.
    """

    __namespace__ = "agentexecutor"

    # Default path to the AgentExecutor.log within the Intune Management Extension directory
    DEFAULT_LOG_PATH = (
        r"sysvol/ProgramData/Microsoft/IntuneManagementExtension/Logs/AgentExecutor.log"
    )

    # --------------------------------------------------------------------------
    # Compatibility Check
    # --------------------------------------------------------------------------

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

    # --------------------------------------------------------------------------
    # Main Parser Function
    # --------------------------------------------------------------------------

    @export(record=AgentExecutorLogRecord)
    def logparser(self) -> Iterator[AgentExecutorLogRecord]:
        """Parse the AgentExecutor.log and yield structured records.

        Extracts timestamp, message, context, thread, and type information from
        the AgentExecutor log and yields normalized structured records.

        Yields:
            AgentExecutorLogRecord: A structured representation of each log entry.
        """
        log_path = self.target.fs.path(self.DEFAULT_LOG_PATH)

        # Try to open the log file safely with fallback on encoding errors
        try:
            with log_path.open("r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            log.exception(f"Failed to open log file {log_path}: {e}")
            return

        match_count = 0

        # Iterate through all regex matches in the file
        for match in LOG_PATTERN.finditer(content):
            match_count += 1

            # Clean and normalize the message content
            msg = match.group("message").replace("\r", "").strip()
            date_str = match.group("date")
            hms_str = match.group("hms")
            fractional_seconds_str = match.group("fractional_seconds")

            # Normalize fractional seconds to microseconds (pad or trim to 6 digits)
            micro_str = (fractional_seconds_str or "000000")[:6].ljust(6, "0")
            time_str = f"{hms_str}.{micro_str}"

            # Attempt to parse datetime using common US/EU date formats
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

            # Normalize timestamp and log type
            iso_timestamp = timestamp.isoformat(timespec="microseconds")
            type_map = {"1": "INFO", "2": "ERROR", "3": "WARNING", "0": "UNKNOWN"}
            log_type = type_map.get(match.group("type"), match.group("type"))

            # Yield structured record
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

        # Warn if no entries matched (useful for troubleshooting regex changes)
        if match_count == 0:
            log.warning(f"No log entries matched the regex in {log_path}")
