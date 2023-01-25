from datetime import datetime, timezone
from typing import Iterator
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dissect.target import plugin
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath, open_decompress
from dissect.target.plugins.os.unix.log.packagemanagers.model import PackageManagerLogRecord, OperationTypes

YUM_LOG_KEYWORDS = ["Installed", "Updated", "Erased", "Obsoleted"]


class YumPlugin(plugin.Plugin):
    __namespace__ = "yum"
    LOGS_DIR_PATH = "/var/log/"
    LOGS_GLOB = "yum.*"

    def __init__(self, target):
        super().__init__(target)

        try:
            self.target_timezone = ZoneInfo(f"{target.timezone}")
        except ZoneInfoNotFoundError:
            self.target.log.warning("Could not determine timezone of target, falling back to UTC.")
            self.target_timezone = timezone.utc

    def check_compatible(self):
        if not self.target.fs.path(self.LOGS_DIR_PATH).glob(self.LOGS_GLOB):
            raise UnsupportedPluginError("No yum logs found")

    def parse_logs(self, log_lines: [str], filepath: TargetPath) -> Iterator[PackageManagerLogRecord]:
        """
        Logs are formatted like this:
            Dec 16 04:41:22 Installed: unzip-6.0-24.el7_9.x86_64
            Dec 16 04:41:25 Installed: unzip-6.0-22.el7_9.x86_64
            Dec 16 04:41:28 Updated: unzip-6.0-24.el7_9.x86_64
            Dec 16 04:41:30 Erased: unzip-6.0-24.el7_9.x86_64
            Dec 16 04:41:34 Installed: unzip-6.0-24.el7_9.x86_64
        """

        file_mtime = self.target.fs.get(str(filepath)).stat().st_mtime
        year_file_modified = datetime.fromtimestamp(file_mtime).year
        last_seen_year = year_file_modified
        last_seen_month = 0

        for line in log_lines:
            # only parse lines that are about installation/erasions/updates, not empty lines or debug statements
            if not any(keyword in line for keyword in YUM_LOG_KEYWORDS):
                continue

            line_ts = datetime.strptime(line[0:15], "%b %d %H:%M:%S")

            # because adding a year to log files is apparently hard for SuSE
            if last_seen_month > line_ts.month:
                last_seen_year += 1
            last_seen_month = line_ts.month

            line_ts = line_ts.replace(year=last_seen_year, tzinfo=self.target_timezone)

            message = line[16:]
            operation, package_name = message.split(": ")
            operation = OperationTypes.infer(operation.strip())

            yield PackageManagerLogRecord(
                package_manager="yum", ts=line_ts, operation=operation.value, package_name=package_name
            )

    @plugin.export(record=PackageManagerLogRecord)
    def logs(self):
        log_file_paths = self.target.fs.path(self.LOGS_DIR_PATH).glob(self.LOGS_GLOB)

        for path in log_file_paths:
            log_lines = [line.strip() for line in open_decompress(path, "rt")]

            yield from self.parse_logs(log_lines, path)
