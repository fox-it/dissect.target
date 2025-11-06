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
# Defines the structure of parsed IntuneManagementExtension log entries.
IntuneManagementExtensionLogRecord = TargetRecordDescriptor(
    "IntuneManagementExtension/log",
    [
        ("datetime", "timestamp"),   # Timestamp of the log entry
        ("string", "component"),     # Log component name (e.g., IntuneManagementExtension)
        ("string", "thread"),        # Thread ID or identifier
        ("string", "type"),          # Log type (e.g., INFO, ERROR)
        ("string", "message"),       # The actual log message
        ("string", "file_origin"),   # Source log file name (useful if multiple)
    ],
)

# ------------------------------------------------------------------------------
# Regular Expression Pattern
# ------------------------------------------------------------------------------
# Matches Intune Management Extension log entries that follow this format:
# <![LOG[<message>]LOG]!><time="HH:MM:SS.FFFFFF" date="MM-DD-YYYY"
# component="..." context="" type="1" thread="1" file="">
LOG_PATTERN = re.compile(
    r'<!\[LOG\[(?P<message>.*?)\]LOG\]!>'                                                                    # Log message
    r'<time="(?P<hms>\d{2}:\d{2}:\d{2})(?:\.(?P<fractional_seconds>\d+))?"\s+'                               # Time (with optional microseconds)
    r'date="(?P<date>[\d-]+)"\s+component="(?P<component>[^"]+)"'                                            # Date and Component
    r'\s+context="[^"]*"\s+type="(?P<type>\d+)"\s+thread="(?P<thread>\d+)"\s+file="(?P<file_origin>[^"]*)"', # Context, Type, Thread, File
    re.DOTALL | re.IGNORECASE,
)

# ------------------------------------------------------------------------------
# Plugin Definition
# ------------------------------------------------------------------------------

class IntuneManagementExtensionLogParserPlugin(Plugin):
    """Parse Microsoft Intune Management Extension logs (including rotated logs).

    This plugin processes both the primary `IntuneManagementExtension.log` file and
    any timestamped rotated versions (e.g. `IntuneManagementExtension-20251009-135155.log`).

    Each parsed entry includes metadata such as timestamp, log type, thread ID,
    component name, and message content.
    """

    __namespace__ = "intunemanagementextension"

    # Default path to the AgentExecutor.log within the Intune Management Extension directory
    LOG_DIR = r"sysvol/ProgramData/Microsoft/IntuneManagementExtension/Logs"

    # --------------------------------------------------------------------------
    # Compatibility Check
    # --------------------------------------------------------------------------

    def check_compatible(self) -> None:
        """Verify that the Intune Management Extension logs exist in the target.

        Raises:
            UnsupportedPluginError: If the log directory or log files are missing.
        """
        log_dir = self.target.fs.path(self.LOG_DIR)
        if not log_dir.exists():
            raise UnsupportedPluginError(
                f"Intune Management Extension log directory not found: {self.LOG_DIR}"
            )

        has_logs = any(
            p.name.lower().startswith("intunemanagementextension") and p.name.lower().endswith(".log")
            for p in log_dir.iterdir()
        )
        if not has_logs:
            raise UnsupportedPluginError("No Intune Management Extension logs found in target.")

    # --------------------------------------------------------------------------
    # Main Parser Function
    # --------------------------------------------------------------------------

    @export(record=IntuneManagementExtensionLogRecord)
    def logparser(self) -> Iterator[IntuneManagementExtensionLogRecord]:
        """Parse Intune Management Extension log files.

        Yields:
            IntuneManagementExtensionLogRecord: One record per parsed log line.
        """
        log_dir = self.target.fs.path(self.LOG_DIR)
        log_files = [
            p for p in log_dir.iterdir()
            if p.name.lower().startswith("intunemanagementextension") and p.name.lower().endswith(".log")
        ]

        if not log_files:
            log.warning(f"No Intune Management Extension log files found under {self.LOG_DIR}")
            return

        # Sort rotated logs by name (chronological order)
        for log_path in sorted(log_files, key=lambda x: x.name):
            try:
                with log_path.open("r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                log.exception(f"Failed to open log file {log_path}: {e}")
                continue

            match_count = 0
            for match in LOG_PATTERN.finditer(content):
                match_count += 1

                # Clean and normalize message text
                msg = match.group("message").replace("\r", "").replace("\n", " ").strip()

                # Combine date and time into a full timestamp
                date_str = match.group("date")
                hms_str = match.group("hms")
                fractional_seconds_str = match.group("fractional_seconds")

                # Normalize microseconds
                micro_str = (fractional_seconds_str or "000000")[:6].ljust(6, "0")
                time_str = f"{hms_str}.{micro_str}"

                # Attempt multiple datetime formats
                timestamp = None
                for fmt in ("%m-%d-%Y %H:%M:%S.%f", "%d-%m-%Y %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f"):
                    try:
                        timestamp = datetime.strptime(f"{date_str} {time_str}", fmt)
                        break
                    except ValueError:
                        continue
                if not timestamp:
                    continue

                # Map type codes to human-readable values
                type_map = {"1": "INFO", "2": "ERROR", "3": "WARNING", "0": "UNKNOWN"}
                log_type = type_map.get(match.group("type"), match.group("type"))

                # Yield parsed record
                yield IntuneManagementExtensionLogRecord(
                    timestamp=timestamp.isoformat(timespec="microseconds"),
                    component=match.group("component"),
                    thread=match.group("thread"),
                    type=log_type,
                    message=msg,
                    file_origin=f"{log_path.name}:{match.group('file_origin')}",
                    _target=self.target,
                )

            if match_count == 0:
                log.warning(f"No log entries matched regex in {log_path}")
